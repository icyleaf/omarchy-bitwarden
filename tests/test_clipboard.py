from unittest.mock import patch, MagicMock
from pathlib import Path
import pytest
from bitwarden_helper.clipboard import ClipboardManager

def test_clipboard_copy_basic():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        cm = ClipboardManager()
        ok = cm.copy("my_secret_text", sensitive=False)
        assert ok is True
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert "wl-copy" in args[0][0]
        assert kwargs.get("input") == "my_secret_text"

def test_clipboard_copy_sensitive_spawns_clear():
    with patch("subprocess.run") as mock_run, \
         patch("subprocess.Popen") as mock_popen:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        cm = ClipboardManager()
        ok = cm.copy("sensitive_password", sensitive=True, timeout_seconds=30)
        assert ok is True
        mock_popen.assert_called_once()
        args, _ = mock_popen.call_args
        cmd_str = " ".join(args[0])
        assert "30" in cmd_str
        assert "wl-copy" in cmd_str
