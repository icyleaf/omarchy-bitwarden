import json
import os
from unittest.mock import patch, MagicMock
import pytest
from bitwarden_helper.auth import AuthManager, AuthStatus, AuthResult

def test_auth_status_unauthenticated():
    with patch("subprocess.run") as mock_run, \
         patch("bitwarden_helper.keyring.KeyringManager.get_session", return_value=None):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"status": "unauthenticated", "serverUrl": "https://vault.bitwarden.com"}),
            stderr=""
        )
        am = AuthManager(bw_path="bw")
        st = am.get_status()
        assert st.status == "unauthenticated"
        assert st.server_url == "https://vault.bitwarden.com"
        assert st.has_session is False

def test_auth_status_locked_with_valid_keyring_session():
    with patch("subprocess.run") as mock_run, \
         patch("bitwarden_helper.keyring.KeyringManager.get_session", return_value="valid_session_key"), \
         patch("bitwarden_helper.auth.AuthManager.verify_session", return_value=True):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"status": "locked", "serverUrl": "https://vault.bitwarden.com", "userEmail": "test@test.com"}),
            stderr=""
        )
        am = AuthManager(bw_path="bw")
        st = am.get_status()
        assert st.status == "unlocked"
        assert st.user_email == "test@test.com"
        assert st.has_session is True

def test_auth_status_locked_with_expired_keyring_session():
    with patch("subprocess.run") as mock_run, \
         patch("bitwarden_helper.keyring.KeyringManager.get_session", return_value="expired_session_key"), \
         patch("bitwarden_helper.keyring.KeyringManager.clear_session") as mock_clear, \
         patch("bitwarden_helper.auth.AuthManager.verify_session", return_value=False):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"status": "locked", "serverUrl": "https://vault.bitwarden.com", "userEmail": "test@test.com"}),
            stderr=""
        )
        am = AuthManager(bw_path="bw")
        st = am.get_status(verify=True)
        assert st.status == "locked"
        assert st.has_session is False
        mock_clear.assert_called_once()


def test_auth_login_password_success():
    with patch("subprocess.run") as mock_run, \
         patch("bitwarden_helper.keyring.KeyringManager.store_session") as mock_store:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="valid_session_token_123",
            stderr=""
        )
        am = AuthManager(bw_path="bw")
        res = am.login_password("test@test.com", "mypassword")
        assert res.ok is True
        assert res.session == "valid_session_token_123"
        mock_store.assert_called_once_with("valid_session_token_123")

def test_auth_login_password_failure():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Invalid master password."
        )
        am = AuthManager(bw_path="bw")
        res = am.login_password("test@test.com", "wrongpassword")
        assert res.ok is False
        assert "Invalid master password" in res.error

def test_auth_login_apikey_success():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="You are logged in!",
            stderr=""
        )
        am = AuthManager(bw_path="bw")
        res = am.login_apikey("client.id", "client.secret")
        assert res.ok is True
        _, kwargs = mock_run.call_args
        env = kwargs.get("env", {})
        assert env.get("BW_CLIENTID") == "client.id"
        assert env.get("BW_CLIENTSECRET") == "client.secret"

def test_auth_unlock_success():
    with patch("subprocess.run") as mock_run, \
         patch("bitwarden_helper.keyring.KeyringManager.store_session", return_value=True) as mock_store:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="raw_session_token_xyz\n",
            stderr=""
        )
        am = AuthManager(bw_path="bw")
        res = am.unlock("mypassword")
        assert res.ok is True
        assert res.session == "raw_session_token_xyz"
        mock_store.assert_called_once_with("raw_session_token_xyz")

def test_auth_lock():
    with patch("subprocess.run") as mock_run, \
         patch("bitwarden_helper.keyring.KeyringManager.clear_session", return_value=True) as mock_clear:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        am = AuthManager(bw_path="bw")
        res = am.lock()
        assert res.ok is True
        assert res.status == "locked"
        mock_clear.assert_called_once()
