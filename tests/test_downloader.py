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

PINNED_VERSION = "0.8.0"
PINNED_TAG = f"omawarden-{PINNED_VERSION}"
PINNED_ARCHIVE = f"omawarden-{PINNED_VERSION}-{TRIPLE}.tar.gz"

UNPINNED_VERSION = "0.9.9"
UNPINNED_TAG = f"omawarden-v{UNPINNED_VERSION}"
UNPINNED_ARCHIVE = f"omawarden-{UNPINNED_VERSION}-{TRIPLE}.tar.gz"

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
        bin_dir = os.path.join(cls.fixture_dir, f"omawarden-{UNPINNED_VERSION}-{TRIPLE}")
        os.makedirs(bin_dir, exist_ok=True)
        bin_path = os.path.join(bin_dir, "omawarden")
        with open(bin_path, "w") as f:
            f.write("#!/bin/sh\necho 'omawarden 0.9.9'\n")
        os.chmod(bin_path, 0o755)

        cls.archive_path = os.path.join(cls.fixture_dir, UNPINNED_ARCHIVE)
        with tarfile.open(cls.archive_path, "w:gz") as tar:
            tar.add(bin_dir, arcname=f"omawarden-{UNPINNED_VERSION}-{TRIPLE}")

        with open(cls.archive_path, "rb") as f:
            cls.archive_bytes = f.read()
        cls.valid_sha256 = hashlib.sha256(cls.archive_bytes).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.fixture_dir, ignore_errors=True)

    def setUp(self):
        self.target_dir = tempfile.mkdtemp()
        self.unpinned_url = f"/icyleaf/omarchy-bitwarden/releases/download/{UNPINNED_TAG}/{UNPINNED_ARCHIVE}"
        self.unpinned_sha_url = f"{self.unpinned_url}.sha256"

        self.pinned_url = f"/icyleaf/omarchy-bitwarden/releases/download/{PINNED_TAG}/{PINNED_ARCHIVE}"
        self.pinned_sha_url = f"{self.pinned_url}.sha256"

        MockGitHubHandler.routes = {
            self.unpinned_url: (200, "application/gzip", self.archive_bytes),
            self.pinned_url: (200, "application/gzip", self.archive_bytes),
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

    def test_default_tag_is_pinned_in_plugin_source_and_rejects_tampered_archive(self):
        """Running with no tag defaults to pinned version (0.8.0) and validates against in-source pinned SHA-256."""
        # The mock archive contains random dummy bytes whose SHA does not match 0.8.0's pinned SHA.
        # It must fail closed immediately without trusting any network metadata.
        proc = self.run_downloader()
        self.assertNotEqual(proc.returncode, 0, "Downloader must exit non-zero when archive mismatch against pinned SHA")
        self.assertIn('"ok":false', proc.stdout)
        self.assertIn("SHA-256 checksum mismatch", proc.stdout)
        installed_bin = os.path.join(self.target_dir, "omawarden")
        self.assertFalse(os.path.exists(installed_bin), "Binary must NOT be installed on checksum mismatch")

    def test_pinned_version_with_matching_sha_succeeds(self):
        """When an archive matches the expected pinned SHA, installation succeeds."""
        proc = self.run_downloader(args=[UNPINNED_TAG, self.valid_sha256])
        self.assertEqual(proc.returncode, 0, f"Downloader with matching pinned sha failed: {proc.stdout} {proc.stderr}")
        self.assertIn('"ok":true', proc.stdout)
        self.assertIn('"verified":true', proc.stdout)
        installed_bin = os.path.join(self.target_dir, "omawarden")
        self.assertTrue(os.path.exists(installed_bin), "Binary must be installed on valid verification")

    def test_pinned_version_with_mismatch_sha_fails_closed(self):
        """When an archive does not match the expected pinned SHA, installation must fail closed."""
        fake_sha = "0000000000000000000000000000000000000000000000000000000000000000"
        proc = self.run_downloader(args=[UNPINNED_TAG, fake_sha])
        self.assertNotEqual(proc.returncode, 0, "Downloader must fail on mismatched pinned SHA")
        self.assertIn('"ok":false', proc.stdout)
        self.assertIn("SHA-256 checksum mismatch", proc.stdout)
        installed_bin = os.path.join(self.target_dir, "omawarden")
        self.assertFalse(os.path.exists(installed_bin), "Binary must NOT be installed on checksum mismatch")

    def test_unpinned_release_requires_gh_for_attestation(self):
        """An unpinned release without gh in PATH must fail closed with actionable alert."""
        MockGitHubHandler.routes[self.unpinned_sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {UNPINNED_ARCHIVE}\n".encode("utf-8")
        )
        clean_bin_dir = tempfile.mkdtemp()
        for cmd in ["bash", "sh", "uname", "which", "tar", "gzip", "sha256sum", "mktemp", "mkdir", "chmod", "cp", "mv", "rm", "find", "cat", "awk", "tr", "grep", "cut", "head", "curl", "sleep", "dirname", "pwd"]:
            cmd_path = shutil.which(cmd)
            if cmd_path:
                os.symlink(cmd_path, os.path.join(clean_bin_dir, cmd))

        try:
            proc = self.run_downloader(args=[UNPINNED_TAG], env_extra={"PATH": clean_bin_dir})
            self.assertNotEqual(proc.returncode, 0, "Unpinned release must fail closed when gh is not found")
            self.assertIn('"ok":false', proc.stdout)
            self.assertIn("GitHub CLI (gh) required for fail-closed provenance verification", proc.stdout)
        finally:
            shutil.rmtree(clean_bin_dir, ignore_errors=True)

    def test_unpinned_release_attestation_failure_fails_closed(self):
        """When gh attestation fails for an unpinned release, download must fail closed even in default mode."""
        MockGitHubHandler.routes[self.unpinned_sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {UNPINNED_ARCHIVE}\n".encode("utf-8")
        )
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(args=[UNPINNED_TAG], env_extra={"PATH": extra_path})
            self.assertNotEqual(proc.returncode, 0, "Downloader must fail closed on unpinned attestation failure")
            self.assertIn('"ok":false', proc.stdout)
            self.assertIn("GitHub Artifact Attestation verification failed", proc.stdout)
            installed_bin = os.path.join(self.target_dir, "omawarden")
            self.assertFalse(os.path.exists(installed_bin), "Binary must NOT be installed on attestation failure")
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

    def test_unpinned_release_attestation_success_succeeds(self):
        """When gh attestation verify succeeds for unpinned release, output must report attestation_verified: true."""
        MockGitHubHandler.routes[self.unpinned_sha_url] = (
            200,
            "text/plain",
            f"{self.valid_sha256}  {UNPINNED_ARCHIVE}\n".encode("utf-8")
        )
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(args=[UNPINNED_TAG], env_extra={"PATH": extra_path})
            self.assertEqual(proc.returncode, 0, f"Downloader failed: {proc.stdout}")
            self.assertIn('"ok":true', proc.stdout)
            self.assertIn('"attestation_verified":true', proc.stdout)
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

    def test_unpinned_release_missing_checksum_fails_closed(self):
        """When checksum file returns 404 for unpinned release, installation must abort."""
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(args=[UNPINNED_TAG], env_extra={"PATH": extra_path})
            self.assertNotEqual(proc.returncode, 0, "Downloader must exit non-zero on missing checksum")
            self.assertIn('"ok":false', proc.stdout)
            self.assertIn("Failed to download SHA-256 checksum file", proc.stdout)
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

    def test_unpinned_release_malformed_checksum_fails_closed(self):
        """When checksum file contains non-hex/HTML error text, installation must abort."""
        MockGitHubHandler.routes[self.unpinned_sha_url] = (
            200,
            "text/plain",
            b"<!DOCTYPE html><html><body>Error 404 Not Found</body></html>\n"
        )
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(args=[UNPINNED_TAG], env_extra={"PATH": extra_path})
            self.assertNotEqual(proc.returncode, 0, "Downloader must exit non-zero on malformed checksum")
            self.assertIn('"ok":false', proc.stdout)
            self.assertIn("Malformed or invalid SHA-256 checksum", proc.stdout)
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

    def test_unpinned_release_checksum_mismatch_fails_closed(self):
        """When archive checksum does not match expected sha256, installation must abort."""
        fake_sha = "0000000000000000000000000000000000000000000000000000000000000000"
        MockGitHubHandler.routes[self.unpinned_sha_url] = (
            200,
            "text/plain",
            f"{fake_sha}  {UNPINNED_ARCHIVE}\n".encode("utf-8")
        )
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(args=[UNPINNED_TAG], env_extra={"PATH": extra_path})
            self.assertNotEqual(proc.returncode, 0, "Downloader must exit non-zero on checksum mismatch")
            self.assertIn('"ok":false', proc.stdout)
            self.assertIn("SHA-256 checksum mismatch", proc.stdout)
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

    def test_strict_mode_with_failing_gh_fails_closed(self):
        """When REQUIRE_ATTESTATION=1 and gh fails, installation must fail closed even on pinned release."""
        mock_bin_dir = tempfile.mkdtemp()
        mock_gh = os.path.join(mock_bin_dir, "gh")
        with open(mock_gh, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(mock_gh, 0o755)

        try:
            extra_path = f"{mock_bin_dir}:{os.environ.get('PATH', '')}"
            proc = self.run_downloader(
                args=[UNPINNED_TAG, self.valid_sha256],
                env_extra={"PATH": extra_path, "REQUIRE_ATTESTATION": "1"}
            )
            self.assertNotEqual(proc.returncode, 0, "Downloader must fail closed when gh attestation fails in strict mode")
            self.assertIn('"ok":false', proc.stdout)
            self.assertIn("GitHub Artifact Attestation verification failed", proc.stdout)
        finally:
            shutil.rmtree(mock_bin_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
