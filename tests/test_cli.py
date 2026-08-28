import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from bitwarden_helper.cli import main

def test_cli_config_get(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "config", "get"]):
        exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["server_url"] == "https://vault.bitwarden.com"
        assert data["bw_path"] == "bw"

def test_cli_config_set(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("sys.argv", [
        "bitwarden-helper",
        "--config", str(config_file),
        "config", "set",
        "--server-url", "https://custom.vaultwarden",
        "--bw-path", "/opt/bw",
        "--auto-lock", "20",
        "--clipboard-clear", "40"
    ]):
        exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["server_url"] == "https://custom.vaultwarden"
        assert data["bw_path"] == "/opt/bw"
        assert data["auto_lock_minutes"] == 20
        assert data["clipboard_clear_seconds"] == 40

def test_cli_health(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.health.resolve_executable", return_value="/usr/bin/bw"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="2026.2.0\n", stderr="")
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "health"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["installed"] is True
            assert data["ok"] is True
            assert data["version"] == "2026.2.0"
