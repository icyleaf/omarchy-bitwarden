import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from bitwarden_helper.cli import main
from bitwarden_helper.auth import AuthStatus, AuthResult

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

def test_cli_auth_status(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.auth.AuthManager.get_status", return_value=AuthStatus(status="locked", user_email="a@b.com", has_session=False)):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "auth", "status"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["status"] == "locked"
            assert data["user_email"] == "a@b.com"

def test_cli_auth_unlock(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.auth.AuthManager.unlock", return_value=AuthResult(ok=True, session="token_123")):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "auth", "unlock", "--password", "pwd"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            assert data["session"] == "token_123"

def test_cli_auth_lock(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.auth.AuthManager.lock", return_value=AuthResult(ok=True, status="locked")):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "auth", "lock"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            assert data["status"] == "locked"

def test_cli_hook_install(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.cli.install_lock_hook", return_value=Path("/tmp/hook.sh")) as mock_inst:
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "hook", "install"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            mock_inst.assert_called_once()
from bitwarden_helper.vault import VaultItem

def test_cli_vault_sync(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.vault.VaultManager.sync", return_value=True):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "vault", "sync"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True

def test_cli_vault_search(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    sample_item = VaultItem(
        id="123",
        name="GitHub",
        type=1,
        type_name="login",
        sub_title="user1",
        favorite=True,
    )
    with patch("bitwarden_helper.vault.VaultManager.fetch_items", return_value=[sample_item]), \
         patch("bitwarden_helper.vault.VaultManager.search", return_value=[sample_item]):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "vault", "search", "--query", "git"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert len(data) == 1
            assert data[0]["name"] == "GitHub"
