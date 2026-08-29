from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import pytest

from bitwarden_helper.attachment import get_attachment, send_notification_with_actions
from bitwarden_helper.cli import main

def test_get_attachment_missing_args():
    res = get_attachment("", "", "")
    assert not res["ok"]
    assert "required" in res["error"].lower()

def test_get_attachment_locked_vault(monkeypatch):
    monkeypatch.setattr("bitwarden_helper.attachment.KeyringManager.get_session", lambda self: None)
    res = get_attachment("item-123", "att-456", "file.pdf")
    assert not res["ok"]
    assert "locked" in res["error"].lower()

@patch("subprocess.Popen")
@patch("subprocess.run")
def test_get_attachment_download_success(mock_run, mock_popen, tmp_path, monkeypatch):
    monkeypatch.setattr("bitwarden_helper.attachment.KeyringManager.get_session", lambda self: "valid-session")
    
    # Mock subprocess.run for bw get attachment and notification
    def fake_run(cmd, *args, **kwargs):
        if "bw" in cmd[0]:
            # Touch destination output file
            out_idx = cmd.index("--output") + 1
            out_file = Path(cmd[out_idx])
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text("dummy attachment content")
            return MagicMock(returncode=0, stdout="Downloaded", stderr="")
        elif cmd[0] == "notify-send":
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0)

    mock_run.side_effect = fake_run

    download_dir = str(tmp_path / "Downloads")
    res = get_attachment(
        item_id="item-123",
        attachment_id="att-456",
        filename="report.pdf",
        output_dir=download_dir,
        open_file=False,
        notify=False,
    )

    assert res["ok"]
    assert res["action"] == "download"
    assert res["filename"] == "report.pdf"
    assert Path(res["path"]).exists()
    assert Path(res["path"]).read_text() == "dummy attachment content"

@patch("subprocess.Popen")
@patch("subprocess.run")
def test_get_attachment_view_success(mock_run, mock_popen, tmp_path, monkeypatch):
    monkeypatch.setattr("bitwarden_helper.attachment.KeyringManager.get_session", lambda self: "valid-session")
    
    def fake_run(cmd, *args, **kwargs):
        if "bw" in cmd[0]:
            out_idx = cmd.index("--output") + 1
            out_file = Path(cmd[out_idx])
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text("preview content")
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0)

    mock_run.side_effect = fake_run

    res = get_attachment(
        item_id="item-999",
        attachment_id="att-777",
        filename="diagram.png",
        open_file=True,
    )

    assert res["ok"]
    assert res["action"] == "view"
    assert res["filename"] == "diagram.png"
    assert "/tmp/omarchy-bitwarden/attachments" in res["path"]
    assert Path(res["path"]).exists()
    mock_popen.assert_called_with(["xdg-open", res["path"]])

@patch("subprocess.run")
def test_cli_attachment_download(mock_run, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("bitwarden_helper.attachment.KeyringManager.get_session", lambda self: "valid-session")

    def fake_run(cmd, *args, **kwargs):
        if "bw" in cmd[0]:
            out_idx = cmd.index("--output") + 1
            out_file = Path(cmd[out_idx])
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text("test")
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0)

    mock_run.side_effect = fake_run

    out_dir = str(tmp_path / "dl")
    exit_code = main(["attachment", "download", "--item-id", "item-1", "--attachment-id", "att-1", "--filename", "key.pem", "--output-dir", out_dir])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["ok"]
    assert data["filename"] == "key.pem"

@patch("subprocess.run")
def test_get_attachment_preview_text(mock_run, tmp_path, monkeypatch):
    monkeypatch.setattr("bitwarden_helper.attachment.KeyringManager.get_session", lambda self: "valid-session")

    def fake_run(cmd, *args, **kwargs):
        if "bw" in cmd[0]:
            out_idx = cmd.index("--output") + 1
            out_file = Path(cmd[out_idx])
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text("API_KEY=12345\nDEBUG=true")
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0)

    mock_run.side_effect = fake_run

    res = get_attachment(
        item_id="item-env",
        attachment_id="att-env",
        filename=".env",
        preview=True,
    )
    assert res["ok"]
    assert res["action"] == "preview"
    assert res["is_text"] is True
    assert "API_KEY=12345" in res["text_content"]

@patch("subprocess.run")
def test_cli_attachment_preview(mock_run, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("bitwarden_helper.attachment.KeyringManager.get_session", lambda self: "valid-session")

    def fake_run(cmd, *args, **kwargs):
        if "bw" in cmd[0]:
            out_idx = cmd.index("--output") + 1
            out_file = Path(cmd[out_idx])
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text("Hello World")
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0)

    mock_run.side_effect = fake_run

    exit_code = main(["attachment", "download", "--item-id", "item-txt", "--attachment-id", "att-txt", "--filename", "hello.txt", "--preview"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["ok"]
    assert data["action"] == "preview"
    assert data["text_content"] == "Hello World"

