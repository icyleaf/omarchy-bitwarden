import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
from typing import Optional, List

from bitwarden_helper.config import ConfigManager, Config
from bitwarden_helper.health import check_cli_health
from bitwarden_helper.auth import AuthManager
from bitwarden_helper.hook import install_lock_hook
from bitwarden_helper.vault import VaultManager
from bitwarden_helper.clipboard import ClipboardManager
from bitwarden_helper.totp import generate_totp

def read_secret_stdin(explicit_arg: Optional[str] = None) -> str:
    if explicit_arg is not None:
        return explicit_arg
    if not sys.stdin.isatty():
        try:
            val = sys.stdin.read()
            if isinstance(val, str) and val != "":
                return val.rstrip("\r\n")
        except Exception:
            return ""
    return ""

def read_auth_payload(explicit_password: Optional[str] = None, explicit_code: Optional[str] = None) -> tuple[str, Optional[str]]:
    if explicit_password is not None:
        return (explicit_password, explicit_code)
    raw = ""
    if not sys.stdin.isatty():
        try:
            raw = sys.stdin.read().strip()
        except Exception:
            raw = ""
    if not raw:
        return ("", explicit_code)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            pwd = str(data.get("password") or "")
            code_val = data.get("code") or explicit_code
            return (pwd, str(code_val) if code_val else None)
    except Exception:
        pass
    lines = raw.split("\n", 1)
    if len(lines) > 1 and lines[1].strip():
        return (lines[0].rstrip("\r"), lines[1].strip())
    return (lines[0].rstrip("\r"), explicit_code)




def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bitwarden-helper",
        description="Helper CLI for Omarchy Bitwarden Plugin"
    )
    parser.add_argument("--config", dest="config_path", help="Path to config.json", default=None)
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_sub = config_parser.add_subparsers(dest="config_action", required=True)
    
    config_sub.add_parser("get", help="Get current configuration")
    
    set_parser = config_sub.add_parser("set", help="Set configuration options")
    set_parser.add_argument("--server-url", dest="server_url", help="Bitwarden server URL")
    set_parser.add_argument("--bw-path", dest="bw_path", help="Path to bitwarden-cli binary")
    set_parser.add_argument("--download-dir", dest="download_dir", help="Default download directory path")
    set_parser.add_argument("--auto-lock", dest="auto_lock_minutes", type=int, help="Auto lock timeout (minutes)")
    set_parser.add_argument("--clipboard-clear", dest="clipboard_clear_seconds", type=int, help="Clipboard clear timeout (seconds)")
    set_parser.add_argument("--max-output-mb", dest="max_output_mb", type=int, help="Maximum vault payload bound (MB)")
    set_parser.add_argument("--email", dest="email", help="Remembered account email")
    set_parser.add_argument("--remember-email", dest="remember_email", type=lambda v: str(v).lower() in ("true", "1", "yes"), help="Remember email flag (true/false)")
    
    # health command
    health_parser = subparsers.add_parser("health", help="Check CLI health and installation")
    health_parser.add_argument("--bw-path", dest="bw_path", help="Override bw binary path to check")
    
    # auth command
    auth_parser = subparsers.add_parser("auth", help="Manage Bitwarden authentication and vault sessions")
    auth_sub = auth_parser.add_subparsers(dest="auth_action", required=True)
    
    auth_sub.add_parser("status", help="Get current authentication and vault lock status")
    
    login_pwd = auth_sub.add_parser("login-password", help="Login using Master Password")
    login_pwd.add_argument("--email", required=True, help="Bitwarden account email")
    login_pwd.add_argument("--password", help="Bitwarden master password (optional flag, stdin preferred)")
    login_pwd.add_argument("--code", help="Two-factor authentication code (optional)")
    
    login_api = auth_sub.add_parser("login-apikey", help="Login using API Key")
    login_api.add_argument("--client-id", required=True, help="Bitwarden Client ID")
    login_api.add_argument("--client-secret", help="Bitwarden Client Secret (optional flag, stdin preferred)")
    
    unlock_cmd = auth_sub.add_parser("unlock", help="Unlock vault with master password")
    unlock_cmd.add_argument("--password", help="Master password (optional flag, stdin preferred)")
    
    auth_sub.add_parser("lock", help="Lock vault and clear session")
    auth_sub.add_parser("logout", help="Logout from Bitwarden account")
    
    # hook command
    hook_parser = subparsers.add_parser("hook", help="Manage system integration hooks")
    hook_sub = hook_parser.add_subparsers(dest="hook_action", required=True)
    hook_sub.add_parser("install", help="Install system-lock hook into Omarchy hooks directory")
    
    # vault command
    vault_parser = subparsers.add_parser("vault", help="Vault sync and search operations")
    vault_sub = vault_parser.add_subparsers(dest="vault_action", required=True)
    
    vault_sub.add_parser("sync", help="Sync vault from Bitwarden server")
    
    list_cmd = vault_sub.add_parser("list", help="List all vault items")
    list_cmd.add_argument("--filter", dest="category", help="Filter by category (login, card, identity, note, ssh_key)")
    
    search_cmd = vault_sub.add_parser("search", help="Search vault items")
    search_cmd.add_argument("--query", dest="query", default="", help="Search query keyword")
    search_cmd.add_argument("--filter", dest="category", help="Filter by category (login, card, identity, note, ssh_key)")
    
    # clipboard command
    clip_parser = subparsers.add_parser("clipboard", help="Wayland clipboard integration")
    clip_sub = clip_parser.add_subparsers(dest="clip_action", required=True)
    
    copy_cmd = clip_sub.add_parser("copy", help="Copy text to clipboard")
    copy_cmd.add_argument("--text", help="Text to copy (optional flag, stdin preferred)")
    copy_cmd.add_argument("--sensitive", action="store_true", help="Mark payload as sensitive for auto-clear")
    copy_cmd.add_argument("--timeout", type=int, default=None, help="Auto-clear timeout in seconds")
    
    clip_sub.add_parser("clear", help="Clear clipboard immediately")
    
    # totp command
    totp_parser = subparsers.add_parser("totp", help="Generate TOTP verification code")
    totp_sub = totp_parser.add_subparsers(dest="totp_action", required=True)
    
    gen_cmd = totp_sub.add_parser("generate", help="Generate TOTP code from secret or otpauth URI")
    gen_cmd.add_argument("--secret", help="Base32 secret or otpauth:// URI (optional flag, stdin preferred)")
    
    # attachment command
    att_parser = subparsers.add_parser("attachment", help="Manage vault item attachments")
    att_sub = att_parser.add_subparsers(dest="att_action", required=True)
    
    att_dl = att_sub.add_parser("download", help="Download or view an attachment")
    att_dl.add_argument("--item-id", required=True, help="Vault item ID")
    att_dl.add_argument("--attachment-id", required=True, help="Attachment ID")
    att_dl.add_argument("--filename", required=True, help="Attachment filename")
    att_dl.add_argument("--output-dir", help="Destination output directory (optional)")
    att_dl.add_argument("--open", action="store_true", help="Open attachment in default application (view mode)")
    att_dl.add_argument("--preview", action="store_true", help="Download to temporary cache for in-overlay inspector preview")
    
    return parser

def main(args: Optional[List[str]] = None) -> int:
    parser = create_parser()
    parsed = parser.parse_args(args)
    
    config_path = Path(parsed.config_path) if parsed.config_path else None
    config_mgr = ConfigManager(config_path=config_path)
    cfg = config_mgr.load()
    max_output_bytes = cfg.max_output_mb * 1024 * 1024
    
    if parsed.command == "config":
        if parsed.config_action == "get":
            print(json.dumps(asdict(cfg), indent=2))
            return 0
        elif parsed.config_action == "set":
            cfg.update(
                server_url=parsed.server_url,
                bw_path=parsed.bw_path,
                auto_lock_minutes=parsed.auto_lock_minutes,
                clipboard_clear_seconds=parsed.clipboard_clear_seconds,
                max_output_mb=parsed.max_output_mb,
                email=parsed.email,
                remember_email=parsed.remember_email,
            )
            config_mgr.save(cfg)
            print(json.dumps(asdict(cfg), indent=2))
            return 0
            
    elif parsed.command == "health":
        bw_path = parsed.bw_path or cfg.bw_path
        status = check_cli_health(bw_path)
        print(json.dumps(asdict(status), indent=2))
        return 0 if status.ok else 1

    elif parsed.command == "auth":
        bw_path = cfg.bw_path
        auth_mgr = AuthManager(bw_path=bw_path, max_output_bytes=max_output_bytes)
        
        if parsed.auth_action == "status":
            st = auth_mgr.get_status()
            print(json.dumps(asdict(st), indent=2))
            return 0
        elif parsed.auth_action == "login-password":
            password, code = read_auth_payload(getattr(parsed, "password", None), getattr(parsed, "code", None))
            res = auth_mgr.login_password(parsed.email, password, code)
            print(json.dumps(asdict(res), indent=2))
            return 0 if res.ok else 1
        elif parsed.auth_action == "login-apikey":
            raw_secret = read_secret_stdin(getattr(parsed, "client_secret", None))
            client_secret = raw_secret
            if raw_secret.startswith("{") and raw_secret.endswith("}"):
                try:
                    payload = json.loads(raw_secret)
                    if isinstance(payload, dict) and "client_secret" in payload:
                        client_secret = str(payload["client_secret"])
                except Exception:
                    pass
            res = auth_mgr.login_apikey(parsed.client_id, client_secret)
            print(json.dumps(asdict(res), indent=2))
            return 0 if res.ok else 1
        elif parsed.auth_action == "unlock":
            password = read_secret_stdin(getattr(parsed, "password", None))
            res = auth_mgr.unlock(password)
            print(json.dumps(asdict(res), indent=2))
            return 0 if res.ok else 1
        elif parsed.auth_action == "lock":
            res = auth_mgr.lock()
            print(json.dumps(asdict(res), indent=2))
            return 0
        elif parsed.auth_action == "logout":
            res = auth_mgr.logout()
            print(json.dumps(asdict(res), indent=2))
            return 0

    elif parsed.command == "hook":
        if parsed.hook_action == "install":
            dest = install_lock_hook()
            print(json.dumps({"ok": True, "installed_path": str(dest)}, indent=2))
            return 0

    elif parsed.command == "vault":
        bw_path = cfg.bw_path
        vault_mgr = VaultManager(bw_path=bw_path, max_output_bytes=max_output_bytes)
        
        if parsed.vault_action == "sync":
            ok = vault_mgr.sync()
            print(json.dumps({"ok": ok}, indent=2))
            return 0 if ok else 1
        elif parsed.vault_action == "list":
            items = vault_mgr.fetch_items()
            filtered = vault_mgr.search(items, query="", category=parsed.category)
            print(json.dumps([asdict(i) for i in filtered], indent=2))
            return 0
        elif parsed.vault_action == "search":
            items = vault_mgr.fetch_items()
            results = vault_mgr.search(items, query=parsed.query, category=parsed.category)
            print(json.dumps([asdict(i) for i in results], indent=2))
            return 0

    elif parsed.command == "clipboard":
        clip_mgr = ClipboardManager()
        if parsed.clip_action == "copy":
            text = read_secret_stdin(getattr(parsed, "text", None))
            timeout = parsed.timeout if parsed.timeout is not None else cfg.clipboard_clear_seconds
            ok = clip_mgr.copy(text, sensitive=parsed.sensitive, timeout_seconds=timeout)
            print(json.dumps({"ok": ok}, indent=2))
            return 0 if ok else 1
        elif parsed.clip_action == "clear":
            ok = clip_mgr.clear()
            print(json.dumps({"ok": ok}, indent=2))
            return 0 if ok else 1

    elif parsed.command == "totp":
        if parsed.totp_action == "generate":
            secret = read_secret_stdin(getattr(parsed, "secret", None))
            totp_res = generate_totp(secret)
            if totp_res:
                print(json.dumps(totp_res, indent=2))
                return 0
            else:
                print(json.dumps({"error": "Invalid TOTP secret"}, indent=2))
                return 1

    elif parsed.command == "attachment":
        from bitwarden_helper.attachment import get_attachment
        if parsed.att_action == "download":
            res = get_attachment(
                item_id=parsed.item_id,
                attachment_id=parsed.attachment_id,
                filename=parsed.filename,
                output_dir=getattr(parsed, "output_dir", None),
                open_file=getattr(parsed, "open", False),
                preview=getattr(parsed, "preview", False),
                bw_path=cfg.bw_path,
            )
            print(json.dumps(res, indent=2))
            return 0 if res.get("ok") else 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
