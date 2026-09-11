#!/usr/bin/env python3
import os
import sys
import shutil
import tempfile
import tarfile
import hashlib
import threading
import subprocess
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler

ARCH = os.uname().machine
if ARCH == "x86_64":
    TRIPLE = "x86_64-unknown-linux-gnu"
elif ARCH in ("aarch64", "arm64"):
    TRIPLE = "aarch64-unknown-linux-gnu"
else:
    TRIPLE = "x86_64-unknown-linux-gnu"

TAG = "omawarden-v0.9.9"
VERSION = "0.9.9"
ARCHIVE_NAME = f"omawarden-{VERSION}-{TRIPLE}.tar.gz"

class MockGitHubHandler(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in self.routes:
            status, content_type, body = self.routes[path]
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            body = b"<html>404 Not Found</html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Suppress request logs

class TestDownloadEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockGitHubHandler)
        cls.port = cls.server.server_port
        cls.server_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

        cls.script_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../scripts/download-engine.sh")
        )

        # Create mock archive
        cls.fixture_dir = tempfile.mkdtemp()
        bin_dir = os.path.join(cls.fixture_dir, f"omawarden-{VERSION}-{TRIPLE}")
        os.makedirs(bin_dir, exist_ok=True)
        bin_path = os.path.join(bin_dir, "omawarden")
        with open(bin_path, "w") as f:
            f.write("#!/bin/sh\necho 'omawarden 0.9.9'\n")
        os.chmod(bin_path, 0o755)

        cls.archive_path = os.path.join(cls.fixture_dir, ARCHIVE_NAME)
        with tarfile.open(cls.archive_path, "w:gz") as tar:
            tar.add(bin_dir, arcname=f"omawarden-{VERSION}-{TRIPLE}")

        with open(cls.archive_path, "rb") as f:
            cls.archive_bytes = f.read()
        cls.valid_sha256 = hashlib.sha256(cls.archive_bytes).hexdigest()

        atom_feed = f"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>tag:github.com,2008:Repository/123/{TAG}</id>
    <link rel="alternate" type="text/html" href="https://github.com/icyleaf/omarchy-bitwarden/releases/tag/{TAG}"/>
    <title>{TAG}</title>
  </entry>
</feed>""".encode("utf-8")
        cls.atom_feed_bytes = atom_feed

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.fixture_dir, ignore_errors=True)

    def setUp(self):
        self.target_dir = tempfile.mkdtemp()
        self.archive_url = f"/icyleaf/omarchy-bitwarden/releases/download/{TAG}/{ARCHIVE_NAME}"
        self.sha_url = f"{self.archive_url}.sha256"

        MockGitHubHandler.routes = {
            "/icyleaf/omarchy-bitwarden/releases.atom": (200, "application/atom+xml", self.atom_feed_bytes),
            self.archive_url: (200, "application/gzip", self.archive_bytes),
        }

    def tearDown(self):
        shutil.rmtree(self.target_dir, ignore_errors=True)

    def run_downloader(self, args=None, env_extra=None):
        env = os.environ.copy()
        env["GITHUB_SERVER_URL"] = self.server_url
        if env_extra:
            env.update(env_extra)

        cmd = ["bash", self.script_path, self.target_dir, "icyleaf/omarchy-bitwarden"]
        if args:
            cmd.extend(args)

        proc = subprocess.run(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return proc

    def test_missing_checksum_fails_closed(self):
        """When checksum file returns 404, installation must abort without extracting or executing."""
        # sha_url is not in routes, so handler returns 404
        proc = self.run_downloader()
        self.assertNotEqual(proc.returncode, 0, "Downloader must exit non-zero on missing checksum")
        self.assertIn('"ok":false', proc.stdout)
        self.assertIn("Failed to download SHA-256 checksum file", proc.stdout)
        installed_bin = os.path.join(self.target_dir, "omawarden")
        self.assertFalse(os.path.exists(installed_bin), "Binary must NOT be installed when checksum download fails")

    def test_malformed_checksum_fails_closed(self):
        """When checksum file contains non-hex/HTML error text, installation must abort."""
        MockGitHubHandler.routes[self.sha_url] = (
            200,
            "text/plain",
            b"<!DOCTYPE html><html><body>Error 404 Not Found</body></html>\n"
        )
        proc = self.run_downloader()
        self.assertNotEqual(proc.returncode, 0, "Downloader must exit non-zero on malformed checksum")
        self.assertIn('"ok":false', proc.stdout)
        self.assertIn("Malformed or invalid SHA-256 checksum", proc.stdout)
        installed_bin = os.path.join(self.target_dir, "omawarden")
        self.assertFalse(os.path.exists(installed_bin), "Binary must NOT be installed when checksum is malformed")

    def test_checksum_mismatch_fails_closed(self):
        """When archive checksum does not match expected sha256, installation must abort."""
        fake_sha = "0000000000000000000000000000000000000000000000000000000000000000"
        MockGitHubHandler.routes[self.sha_url] = (
            200,
            "text/plain",
            f"{fake_sha}  {ARCHIVE_NAME}\n".encode("utf-8")
        )
        proc = self.run_downloader()
        self.assertNotEqual(proc.returncode, 0, "Downloader must exit non-zero on checksum mismatch")
        self.assertIn('"ok":false', proc.stdout)
        self.assertIn("SHA-256 checksum mismatch", proc.stdout)
        installed_bin = os.path.join(self.target_dir, "omawarden")
        self.assertFalse(os.path.exists(installed_bin), "Binary must NOT be installed on checksum mismatch")

    def test_valid_checksum_succeeds_and_verifies(self):
        """When archive and checksum match, installation must succeed and report verified: true."""
        MockGitHubHandler.routes[self.sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {ARCHIVE_NAME}\n".encode("utf-8")
        )
        proc = self.run_downloader()
        self.assertEqual(proc.returncode, 0, f"Downloader failed: {proc.stdout} {proc.stderr}")
        self.assertIn('"ok":true', proc.stdout)
        self.assertIn('"verified":true', proc.stdout)
        installed_bin = os.path.join(self.target_dir, "omawarden")
        self.assertTrue(os.path.exists(installed_bin), "Binary must be installed on valid verification")
        self.assertTrue(os.access(installed_bin, os.X_OK), "Installed binary must be executable")

    def test_pinned_version_argument(self):
        """Explicitly passing pinned tag argument must bypass dynamic feed resolution."""
        pinned_tag = "omawarden-v0.9.9"
        MockGitHubHandler.routes[self.sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {ARCHIVE_NAME}\n".encode("utf-8")
        )
        # Even if atom feed returns 404, pinned version must succeed directly
        del MockGitHubHandler.routes["/icyleaf/omarchy-bitwarden/releases.atom"]

        proc = self.run_downloader(args=[pinned_tag])
        self.assertEqual(proc.returncode, 0, f"Downloader with pinned tag failed: {proc.stdout} {proc.stderr}")
        self.assertIn('"ok":true', proc.stdout)
        self.assertIn('"verified":true', proc.stdout)

    def test_attestation_verification_success_reports_true(self):
        """When gh attestation verify succeeds, output must include attestation_verified: true."""
        MockGitHubHandler.routes[self.sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {ARCHIVE_NAME}\n".encode("utf-8")
        )
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(env_extra={"PATH": extra_path})
            self.assertEqual(proc.returncode, 0, f"Downloader failed: {proc.stdout}")
            self.assertIn('"attestation_verified":true', proc.stdout)
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

    def test_attestation_verification_failure_fallback_in_default_mode(self):
        """When gh attestation fails but strict mode is disabled, download succeeds with attestation_verified: false."""
        MockGitHubHandler.routes[self.sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {ARCHIVE_NAME}\n".encode("utf-8")
        )
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(env_extra={"PATH": extra_path})
            self.assertEqual(proc.returncode, 0, f"Downloader failed: {proc.stdout}")
            self.assertIn('"attestation_verified":false', proc.stdout)
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

    def test_attestation_verification_failure_fails_closed_in_strict_mode(self):
        """When gh attestation fails and REQUIRE_ATTESTATION=1, download must fail closed."""
        MockGitHubHandler.routes[self.sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {ARCHIVE_NAME}\n".encode("utf-8")
        )
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(env_extra={"PATH": extra_path, "REQUIRE_ATTESTATION": "1"})
            self.assertNotEqual(proc.returncode, 0, "Downloader must fail non-zero in strict mode")
            self.assertIn('"ok":false', proc.stdout)
            self.assertIn("GitHub Artifact Attestation verification failed", proc.stdout)
            installed_bin = os.path.join(self.target_dir, "omawarden")
            self.assertFalse(os.path.exists(installed_bin), "Binary must NOT be installed on attestation failure")
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

    def test_attestation_missing_gh_fails_closed_in_strict_mode(self):
        """When gh is missing and REQUIRE_ATTESTATION=1, download must fail closed."""
        MockGitHubHandler.routes[self.sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {ARCHIVE_NAME}\n".encode("utf-8")
        )
        # Create a restricted PATH without gh
        clean_bin_dir = tempfile.mkdtemp()
        for cmd in ["bash", "sh", "uname", "which", "tar", "gzip", "sha256sum", "mktemp", "mkdir", "chmod", "cp", "mv", "rm", "find", "cat", "awk", "tr", "grep", "cut", "head", "curl", "sleep"]:
            cmd_path = shutil.which(cmd)
            if cmd_path:
                os.symlink(cmd_path, os.path.join(clean_bin_dir, cmd))

        try:
            proc = self.run_downloader(env_extra={"PATH": clean_bin_dir, "REQUIRE_ATTESTATION": "1"})
            self.assertNotEqual(proc.returncode, 0, "Downloader must fail non-zero when gh is missing in strict mode")
            self.assertIn('"ok":false', proc.stdout)
            self.assertIn("GitHub CLI (gh) required for strict attestation verification", proc.stdout)
        finally:
            shutil.rmtree(clean_bin_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
