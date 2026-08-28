from unittest.mock import patch, MagicMock
import subprocess
import pytest
from bitwarden_helper.keyring import KeyringManager

def test_keyring_store_session():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        km = KeyringManager()
        success = km.store_session("test_session_token_123")
        assert success is True
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert "store" in args[0]
        assert kwargs.get("input") == "test_session_token_123"

def test_keyring_get_session_found():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="test_session_token_123\n", stderr="")
        km = KeyringManager()
        token = km.get_session()
        assert token == "test_session_token_123"

def test_keyring_get_session_not_found():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="lookup failed")
        km = KeyringManager()
        token = km.get_session()
        assert token is None

def test_keyring_clear_session():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        km = KeyringManager()
        success = km.clear_session()
        assert success is True
        args, _ = mock_run.call_args
        assert "clear" in args[0]
