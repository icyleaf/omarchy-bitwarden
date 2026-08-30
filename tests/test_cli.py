import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from bitwarden_helper.cli import main
from bitwarden_helper.auth import AuthStatus, AuthResult
from bitwarden_helper.vault import VaultItem

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

def test_cli_auth_login_password_json_payload(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.auth.AuthManager.login_password", return_value=AuthResult(ok=True, session="token_jwt")) as mock_login, \
         patch("sys.stdin.isatty", return_value=False), \
         patch("sys.stdin.read", return_value=json.dumps({"password": "secure_pwd", "code": "987654"})):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "auth", "login-password", "--email", "user@example.com"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            assert data["session"] == "token_jwt"
            mock_login.assert_called_once_with("user@example.com", "secure_pwd", "987654")

def test_cli_auth_login_password_multiline_payload(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.auth.AuthManager.login_password", return_value=AuthResult(ok=True, session="token_jwt")) as mock_login, \
         patch("sys.stdin.isatty", return_value=False), \
         patch("sys.stdin.read", return_value="secure_pwd\n987654\n"):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "auth", "login-password", "--email", "user@example.com"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            mock_login.assert_called_once_with("user@example.com", "secure_pwd", "987654")

def test_cli_auth_login_apikey_stdin_json(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.auth.AuthManager.login_apikey", return_value=AuthResult(ok=True, status="locked")) as mock_api, \
         patch("sys.stdin.isatty", return_value=False), \
         patch("sys.stdin.read", return_value=json.dumps({"client_secret": "my_super_secret"})):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "auth", "login-apikey", "--client-id", "user.xyz"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            mock_api.assert_called_once_with("user.xyz", "my_super_secret")

def test_cli_auth_login_apikey_stdin_raw(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.auth.AuthManager.login_apikey", return_value=AuthResult(ok=True, status="locked")) as mock_api, \
         patch("sys.stdin.isatty", return_value=False), \
         patch("sys.stdin.read", return_value="raw_secret_key_123"):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "auth", "login-apikey", "--client-id", "user.xyz"]):
            exit_code = main()
            assert exit_code == 0
            mock_api.assert_called_once_with("user.xyz", "raw_secret_key_123")

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

def test_cli_clipboard_copy(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.cli.ClipboardManager.copy", return_value=True) as mock_copy:
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "clipboard", "copy", "--text", "pass123", "--sensitive"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            mock_copy.assert_called_once_with("pass123", sensitive=True, timeout_seconds=30)

def test_cli_totp_generate(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.cli.generate_totp", return_value={"code": "123456", "ttl": 15, "period": 30}):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "totp", "generate", "--secret", "JBSWY3DPEHPK3PXP"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["code"] == "123456"
            assert data["ttl"] == 15

def test_cli_auth_unlock_stdin(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.auth.AuthManager.unlock", return_value=AuthResult(ok=True, session="token_via_stdin")) as mock_unlock, \
         patch("sys.stdin.isatty", return_value=False), \
         patch("sys.stdin.readline", return_value="secret_master_password\n"), \
         patch("sys.stdin.read", return_value="secret_master_password\n"):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "auth", "unlock"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            mock_unlock.assert_called_once_with("secret_master_password")

def test_cli_clipboard_copy_stdin(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.cli.ClipboardManager.copy", return_value=True) as mock_copy, \
         patch("sys.stdin.isatty", return_value=False), \
         patch("sys.stdin.readline", return_value="my_sensitive_password\n"), \
         patch("sys.stdin.read", return_value="my_sensitive_password"):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "clipboard", "copy", "--sensitive"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["ok"] is True
            mock_copy.assert_called_once_with("my_sensitive_password", sensitive=True, timeout_seconds=30)

def test_cli_totp_generate_stdin(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("bitwarden_helper.cli.generate_totp", return_value={"code": "654321", "ttl": 28, "period": 30}) as mock_gen, \
         patch("sys.stdin.isatty", return_value=False), \
         patch("sys.stdin.readline", return_value="HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\n"), \
         patch("sys.stdin.read", return_value="HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\n"):
        with patch("sys.argv", ["bitwarden-helper", "--config", str(config_file), "totp", "generate"]):
            exit_code = main()
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["code"] == "654321"
            mock_gen.assert_called_once_with("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")


def test_cli_config_set_max_output(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("sys.argv", [
        "bitwarden-helper",
        "--config", str(config_file),
        "config", "set",
        "--max-output-mb", "25"
    ]):
        exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["max_output_mb"] == 25

def test_cli_config_set_email(tmp_path: Path, capsys):
    config_file = tmp_path / "config.json"
    with patch("sys.argv", [
        "bitwarden-helper",
        "--config", str(config_file),
        "config", "set",
        "--email", "bob@example.com",
        "--remember-email", "false"
    ]):
        exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["email"] == "bob@example.com"
        assert data["remember_email"] is False
