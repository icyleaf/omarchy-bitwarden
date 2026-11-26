#!/usr/bin/env python3
"""Integration tests for scripts/test-qml.sh and scripts/test-all.sh contracts."""

from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class RunnerFixture:
    """Minimal isolated repository copy for exercising real runner scripts."""

    def __init__(self, tmpdir: Path) -> None:
        self.root = tmpdir / "repo"
        self.scripts_dir = self.root / "scripts"
        self.tests_dir = self.root / "tests"
        self.components_dir = self.root / "components"
        self.omawarden_dir = self.root / "omawarden"
        self.bin_dir = tmpdir / "bin"
        self.logs_dir = tmpdir / "logs"

        for d in (
            self.scripts_dir,
            self.tests_dir / "stubs",
            self.components_dir,
            self.omawarden_dir,
            self.bin_dir,
            self.logs_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        shutil.copy2(REPO_ROOT / "scripts" / "test-qml.sh", self.scripts_dir / "test-qml.sh")
        shutil.copy2(REPO_ROOT / "scripts" / "test-all.sh", self.scripts_dir / "test-all.sh")

        write_executable(
            self.scripts_dir / "check-hardcoded-colors.py",
            "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n",
        )
        write_executable(
            self.scripts_dir / "check-qml-module.py",
            "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n",
        )
        write_executable(
            self.tests_dir / "test_workflow_action_pinning.py",
            "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n",
        )
        # Prevent recursive self-invocation inside the fixture repo copy
        write_executable(
            self.tests_dir / "test_runner_scripts.py",
            "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n",
        )
        (self.root / "OmarchyBitwarden.qml").write_text("import QtQuick\nItem {}\n", encoding="utf-8")
        (self.components_dir / "Sample.qml").write_text("import QtQuick\nItem {}\n", encoding="utf-8")
        (self.tests_dir / "tst_alpha.qml").write_text("import QtQuick\nItem {}\n", encoding="utf-8")
        (self.tests_dir / "tst_beta.qml").write_text("import QtQuick\nItem {}\n", encoding="utf-8")

        write_executable(
            self.bin_dir / "qmllint",
            "#!/usr/bin/env bash\nexit 0\n",
        )

        self.qml_log = self.logs_dir / "qml6.log"
        self.hyprctl_log = self.logs_dir / "hyprctl.log"
        self.cargo_log = self.logs_dir / "cargo.log"
        self.install_qml6_stub()
        self.install_cargo_stub()

    def install_qml6_stub(
        self,
        *,
        stdout_line: str = "",
        stderr_line: str = "",
        exit_code: int = 0,
        sleep_seconds: float = 0.0,
        ready_marker: Path | None = None,
    ) -> None:
        marker_cmd = f'touch "{ready_marker}"\n' if ready_marker else ""
        out_cmd = f'printf "%s\\n" "{stdout_line}"\n' if stdout_line else ""
        err_cmd = f'printf "%s\\n" "{stderr_line}" >&2\n' if stderr_line else ""
        tail_cmd = f"exec sleep {sleep_seconds}\n" if sleep_seconds > 0 else f"exit {exit_code}\n"
        write_executable(
            self.bin_dir / "qml6",
            f"""#!/usr/bin/env bash
printf 'QT_QPA_PLATFORM=%s ARGS=%s\\n' "${{QT_QPA_PLATFORM:-<unset>}}" "$*" >> "{self.qml_log}"
{marker_cmd}{out_cmd}{err_cmd}{tail_cmd}""",
        )

    def install_hyprctl_stub(
        self,
        *,
        reject_eval: bool = False,
        stdout_error_on_keyword_disable: bool = False,
    ) -> None:
        eval_branch = (
            'if [ "${1:-}" = "eval" ]; then\n  echo "unknown request"\n  exit 1\nfi\n'
            if reject_eval
            else ""
        )
        disable_branch = (
            'case "$*" in\n'
            '  *":enable false"*)\n'
            '    echo "invalid field enable"\n'
            '    exit 0\n'
            '    ;;\n'
            'esac\n'
            if stdout_error_on_keyword_disable
            else ""
        )
        write_executable(
            self.bin_dir / "hyprctl",
            f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "{self.hyprctl_log}"
{eval_branch}{disable_branch}echo "ok"
exit 0
""",
        )

    def install_cargo_stub(self, *, hang_on_test: bool = False) -> None:
        test_branch = (
            'if [ "${1:-}" = "test" ]; then\n'
            '  echo "running test daemon::tests::simulated_stuck_env_lock ..."\n'
            "  exec sleep 30\n"
            "fi\n"
            if hang_on_test
            else ""
        )
        write_executable(
            self.bin_dir / "cargo",
            f"""#!/usr/bin/env bash
printf 'ARGS=%s XDG_RUNTIME_DIR=%s\\n' "$*" "${{XDG_RUNTIME_DIR:-<unset>}}" >> "{self.cargo_log}"
{test_branch}exit 0
""",
        )

    def base_env(self, extra: dict[str, str | None] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        for key in (
            "QT_QPA_PLATFORM",
            "HYPRLAND_INSTANCE_SIGNATURE",
            "QML_HYPRLAND_WORKSPACE",
            "WAYLAND_DISPLAY",
            "DISPLAY",
            "QML_TEST_TIMEOUT",
            "CARGO_TEST_TIMEOUT",
        ):
            env.pop(key, None)

        util_dir = self.root.parent / "sysbin"
        util_dir.mkdir(parents=True, exist_ok=True)
        for tool in (
            "bash",
            "sh",
            "env",
            "python3",
            "timeout",
            "mktemp",
            "mkdir",
            "rm",
            "dirname",
            "cat",
            "grep",
            "printf",
            "sleep",
            "kill",
            "tr",
            "touch",
        ):
            src = shutil.which(tool)
            dst = util_dir / tool
            if src and not dst.exists():
                dst.symlink_to(src)

        env["PATH"] = f"{self.bin_dir}:{util_dir}"
        if extra:
            for k, v in extra.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v
        return env


class TestQmlRunnerContract(unittest.TestCase):
    def test_default_overrides_inherited_wayland_platform_to_offscreen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            env = fx.base_env(
                {
                    "QT_QPA_PLATFORM": "wayland;xcb",
                    "HYPRLAND_INSTANCE_SIGNATURE": "fake-hypr-sig",
                }
            )
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-qml.sh")],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            lines = fx.qml_log.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)
            for line in lines:
                self.assertIn("QT_QPA_PLATFORM=offscreen ", line)

    def test_qml_runner_help_documents_headless_and_workspace_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-qml.sh"), "--help"],
                env=fx.base_env(),
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("offscreen", proc.stdout)
            self.assertIn("--workspace", proc.stdout)
            self.assertIn("QML_HYPRLAND_WORKSPACE", proc.stdout)
            self.assertFalse(fx.qml_log.exists(), "--help must not execute QML suites")

    def test_workspace_flag_and_env_precedence_register_and_cleanup_hyprland_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            fx.install_hyprctl_stub()
            fx.install_qml6_stub(stdout_line="SUITE_STDOUT_OK", stderr_line="SUITE_STDERR_DIAG")

            env = fx.base_env(
                {
                    "QT_QPA_PLATFORM": "wayland;xcb",
                    "HYPRLAND_INSTANCE_SIGNATURE": "hypr-sig-123",
                    "QML_HYPRLAND_WORKSPACE": "9",
                }
            )
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-qml.sh"), "--workspace", "special:qml-test"],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("SUITE_STDOUT_OK", proc.stdout)
            self.assertIn("SUITE_STDERR_DIAG", proc.stderr)

            qml_lines = fx.qml_log.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(qml_lines), 2)
            for line in qml_lines:
                self.assertIn("QT_QPA_PLATFORM=wayland ", line)

            hypr_calls = fx.hyprctl_log.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreaterEqual(len(hypr_calls), 2, f"Expected register + cleanup calls, got: {hypr_calls}")
            self.assertIn("special:qml-test silent", hypr_calls[0])
            self.assertNotIn('workspace = "9 silent"', hypr_calls[0])
            self.assertTrue(
                "no_initial_focus" in hypr_calls[0] or "noinitialfocus" in hypr_calls[0],
                f"Expected no-focus rule in: {hypr_calls[0]}",
            )
            self.assertTrue(
                "set_enabled(false)" in hypr_calls[-1] or "enable false" in hypr_calls[-1],
                f"Expected rule cleanup in: {hypr_calls[-1]}",
            )

    def test_env_workspace_failure_propagates_exit_code_and_cleans_up_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            fx.install_hyprctl_stub(reject_eval=True)
            fx.install_qml6_stub(stderr_line="ASSERTION_FAILED_IN_QML", exit_code=17)

            env = fx.base_env(
                {
                    "HYPRLAND_INSTANCE_SIGNATURE": "hypr-sig-legacy",
                    "QML_HYPRLAND_WORKSPACE": "8",
                }
            )
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-qml.sh")],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 17)
            self.assertIn("ASSERTION_FAILED_IN_QML", proc.stderr)

            hypr_calls = fx.hyprctl_log.read_text(encoding="utf-8").strip().splitlines()
            joined = "\n".join(hypr_calls)
            self.assertIn("8 silent", joined)
            self.assertIn(
                "enable false",
                hypr_calls[-1],
                f"Expected keyword cleanup on failure, got: {hypr_calls}",
            )

    def test_keyword_cleanup_warns_without_reload_when_disable_reports_stdout_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            fx.install_hyprctl_stub(reject_eval=True, stdout_error_on_keyword_disable=True)
            env = fx.base_env(
                {
                    "HYPRLAND_INSTANCE_SIGNATURE": "hypr-sig-legacy-err",
                    "QML_HYPRLAND_WORKSPACE": "8",
                }
            )
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-qml.sh")],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("WARNING:", proc.stderr)
            hypr_calls = fx.hyprctl_log.read_text(encoding="utf-8").strip().splitlines()
            self.assertFalse(
                any("reload" in line for line in hypr_calls),
                f"Cleanup must not wipe runtime compositor config via reload: {hypr_calls}",
            )

    def test_workspace_sigterm_cleans_up_temporary_hyprland_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            fx.install_hyprctl_stub()
            ready = Path(tmp) / "qml_started"
            fx.install_qml6_stub(sleep_seconds=10.0, ready_marker=ready)

            env = fx.base_env(
                {
                    "HYPRLAND_INSTANCE_SIGNATURE": "hypr-sig-term",
                    "QML_HYPRLAND_WORKSPACE": "special:qml-sigterm",
                }
            )
            proc = subprocess.Popen(
                [str(fx.scripts_dir / "test-qml.sh")],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            deadline = time.monotonic() + 5.0
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(ready.exists(), "qml6 stub did not start before deadline")

            os.killpg(proc.pid, signal.SIGTERM)
            proc.communicate(timeout=10)
            self.assertNotEqual(proc.returncode, 0)

            hypr_calls = fx.hyprctl_log.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreaterEqual(len(hypr_calls), 2, f"Expected register + SIGTERM cleanup, got: {hypr_calls}")
            self.assertIn("special:qml-sigterm silent", hypr_calls[0])
            self.assertIn("set_enabled(false)", hypr_calls[-1])

    def test_non_hyprland_fallback_warns_and_runs_offscreen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            fx.install_hyprctl_stub()
            env = fx.base_env({"QT_QPA_PLATFORM": "wayland;xcb"})
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-qml.sh"), "--workspace", "special:qml-test"],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("offscreen", proc.stderr.lower())
            self.assertFalse(fx.hyprctl_log.exists(), "hyprctl must not be called outside Hyprland")
            for line in fx.qml_log.read_text(encoding="utf-8").strip().splitlines():
                self.assertIn("QT_QPA_PLATFORM=offscreen ", line)

        with tempfile.TemporaryDirectory() as tmp2:
            fx2 = RunnerFixture(Path(tmp2))
            env2 = fx2.base_env(
                {
                    "QT_QPA_PLATFORM": "wayland;xcb",
                    "HYPRLAND_INSTANCE_SIGNATURE": "sig-without-hyprctl",
                    "QML_HYPRLAND_WORKSPACE": "7",
                }
            )
            proc2 = subprocess.run(
                [str(fx2.scripts_dir / "test-qml.sh")],
                env=env2,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc2.returncode, 0, msg=proc2.stderr)
            self.assertIn("offscreen", proc2.stderr.lower())
            for line in fx2.qml_log.read_text(encoding="utf-8").strip().splitlines():
                self.assertIn("QT_QPA_PLATFORM=offscreen ", line)


class TestFullRunnerContract(unittest.TestCase):
    def test_full_runner_help_documents_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-all.sh"), "--help"],
                env=fx.base_env(),
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("offscreen", proc.stdout)
            self.assertIn("--workspace", proc.stdout)
            self.assertIn("QML_HYPRLAND_WORKSPACE", proc.stdout)
            self.assertFalse(fx.cargo_log.exists(), "--help must not run cargo")

    def test_full_runner_runs_parallel_cargo_and_forwards_workspace_to_qml_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            fx.install_hyprctl_stub()
            env = fx.base_env(
                {
                    "QT_QPA_PLATFORM": "wayland;xcb",
                    "HYPRLAND_INSTANCE_SIGNATURE": "hypr-sig-all",
                    "QML_HYPRLAND_WORKSPACE": "5",
                }
            )
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-all.sh"), "--workspace", "special:full-suite"],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)

            cargo_calls = fx.cargo_log.read_text(encoding="utf-8")
            self.assertIn("ARGS=test --all-targets", cargo_calls)
            self.assertNotIn("--test-threads=1", cargo_calls)

            hypr_calls = fx.hyprctl_log.read_text(encoding="utf-8").strip().splitlines()
            self.assertIn("special:full-suite silent", hypr_calls[0])
            self.assertIn("set_enabled(false)", hypr_calls[-1])

    def test_full_runner_enforces_bounded_timeout_on_hung_cargo_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fx = RunnerFixture(Path(tmp))
            fx.install_cargo_stub(hang_on_test=True)
            env = fx.base_env({"CARGO_TEST_TIMEOUT": "1s"})

            start = time.monotonic()
            proc = subprocess.run(
                [str(fx.scripts_dir / "test-all.sh")],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            elapsed = time.monotonic() - start
            self.assertNotEqual(proc.returncode, 0, "Hung cargo test must fail non-zero")
            self.assertLess(elapsed, 6.0, "Timeout guardrail must terminate hung cargo test promptly")
            combined = f"{proc.stdout}\n{proc.stderr}"
            self.assertIn("simulated_stuck_env_lock", combined)
            self.assertIn("timed out", combined.lower())


if __name__ == "__main__":
    unittest.main()
