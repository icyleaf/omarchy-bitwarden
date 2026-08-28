from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess
import pytest
from bitwarden_helper.health import check_cli_health, HealthStatus

def test_health_check_with_valid_executable():
    with patch("shutil.which", return_value="/usr/bin/bw"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="2026.2.0\n",
            stderr=""
        )
        status = check_cli_health("bw")
        assert status.installed is True
        assert status.ok is True
        assert status.version == "2026.2.0"
        assert status.executable_path == "/usr/bin/bw"
        assert status.error is None

def test_health_check_missing_binary():
    with patch("shutil.which", return_value=None):
        status = check_cli_health("/nonexistent/bw")
        assert status.installed is False
        assert status.ok is False
        assert status.version is None
        assert "not found" in status.error.lower()

def test_health_check_failing_binary():
    with patch("shutil.which", return_value="/usr/bin/bw"), \
         patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.SubprocessError("Failed to execute")
        status = check_cli_health("bw")
        assert status.installed is True
        assert status.ok is False
        assert "failed to execute" in status.error.lower()
