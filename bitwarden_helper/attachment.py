from pathlib import Path
import os
import subprocess
import threading
from typing import Dict, Any, Optional

from bitwarden_helper.keyring import KeyringManager
from bitwarden_helper.config import ConfigManager, DEFAULT_DOWNLOAD_DIR

def send_notification_with_actions(title: str, body: str, file_path: Path) -> None:
    def _worker():
        try:
            res = subprocess.run(
                [
                    "notify-send",
                    "--app-name=Bitwarden",
                    "-i", "document-save",
                    "-A", "open=Open File",
                    "-A", "folder=Open Folder",
                    title,
                    body,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            action = res.stdout.strip()
            if action == "open":
                subprocess.Popen(["xdg-open", str(file_path)])
            elif action == "folder":
                subprocess.Popen(["xdg-open", str(file_path.parent)])
        except Exception:
            try:
                subprocess.run(
                    ["notify-send", "--app-name=Bitwarden", "-i", "document-save", title, body],
                    check=False,
                )
            except Exception:
                pass

    t = threading.Thread(target=_worker, daemon=False)
    t.start()

def get_attachment(
    item_id: str,
    attachment_id: str,
    filename: str,
    output_dir: Optional[str] = None,
    open_file: bool = False,
    preview: bool = False,
    session_token: Optional[str] = None,
    bw_path: Optional[str] = None,
    notify: bool = True,
) -> Dict[str, Any]:
    if not item_id or not attachment_id:
        return {"ok": False, "error": "Item ID and Attachment ID are required."}
    
    cfg = ConfigManager().load()
    bw_bin = bw_path or cfg.bw_path or "bw"

    token = session_token
    if not token:
        token = KeyringManager().get_session()
    
    if not token:
        return {"ok": False, "error": "Vault is locked or session has expired."}
    
    safe_filename = Path(filename or f"attachment_{attachment_id}").name
    if not safe_filename or safe_filename == ".":
        safe_filename = f"attachment_{attachment_id}"

    if open_file or preview:
        target_dir = Path("/tmp/omarchy-bitwarden/attachments") / item_id
    else:
        dest_dir_str = output_dir or cfg.download_dir or DEFAULT_DOWNLOAD_DIR
        target_dir = Path(os.path.expanduser(dest_dir_str))

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return {"ok": False, "error": f"Failed to create target directory: {e}"}

    dest_path = target_dir / safe_filename

    env = os.environ.copy()
    env["BW_SESSION"] = token

    cmd = [
        bw_bin,
        "get",
        "attachment",
        attachment_id,
        "--itemid",
        item_id,
        "--output",
        str(dest_path),
    ]

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Attachment download timed out."}
    except FileNotFoundError:
        return {"ok": False, "error": f"Bitwarden CLI executable '{bw_bin}' not found."}
    except Exception as e:
        return {"ok": False, "error": f"Failed to execute download command: {e}"}

    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or proc.stdout.strip() or "Failed to download attachment."
        if "not found" in err_msg.lower():
            err_msg = "Attachment not found on server."
        elif "session" in err_msg.lower() or "unauthorized" in err_msg.lower():
            err_msg = "Session expired. Please unlock your vault."
        return {"ok": False, "error": err_msg}

    if not dest_path.exists():
        return {"ok": False, "error": "Downloaded file was not created on disk."}

    ext = dest_path.suffix.lower().lstrip(".")
    is_image = ext in ("png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico")
    is_text = ext in (
        "txt", "md", "json", "yaml", "yml", "csv", "log", "sh", "bash", "zsh",
        "py", "js", "ts", "html", "css", "xml", "conf", "config", "ini", "env",
        "pem", "key", "pub", "crt", "cer", "diff", "patch", "sql", "toml", "lua"
    )

    text_content = ""
    if is_text or (not is_image and dest_path.stat().st_size <= 1024 * 1024):
        try:
            with open(dest_path, "r", encoding="utf-8", errors="replace") as f:
                text_content = f.read(500000)
            if not is_text:
                # Check if readable ascii/utf-8 text without control characters
                if "\x00" not in text_content:
                    is_text = True
                else:
                    text_content = ""
        except Exception:
            text_content = ""

    if open_file:
        try:
            subprocess.Popen(["xdg-open", str(dest_path)])
        except Exception:
            pass
        return {
            "ok": True,
            "path": str(dest_path),
            "filename": safe_filename,
            "action": "view",
            "is_image": is_image,
            "is_text": is_text,
            "text_content": text_content,
            "size": dest_path.stat().st_size,
        }
    elif preview:
        return {
            "ok": True,
            "path": str(dest_path),
            "filename": safe_filename,
            "action": "preview",
            "is_image": is_image,
            "is_text": is_text,
            "text_content": text_content,
            "size": dest_path.stat().st_size,
        }
    else:
        if notify:
            send_notification_with_actions(
                "Bitwarden Attachment",
                f"Saved {safe_filename} to {target_dir}",
                dest_path,
            )
        return {
            "ok": True,
            "path": str(dest_path),
            "filename": safe_filename,
            "action": "download",
            "is_image": is_image,
            "is_text": is_text,
            "size": dest_path.stat().st_size,
        }
