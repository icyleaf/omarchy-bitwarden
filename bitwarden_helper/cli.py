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
    set_parser.add_argument("--auto-lock", dest="auto_lock_minutes", type=int, help="Auto lock timeout (minutes)")
    set_parser.add_argument("--clipboard-clear", dest="clipboard_clear_seconds", type=int, help="Clipboard clear timeout (seconds)")
    
    # health command
    health_parser = subparsers.add_parser("health", help="Check CLI health and installation")
    health_parser.add_argument("--bw-path", dest="bw_path", help="Override bw binary path to check")
    
    # auth command
    auth_parser = subparsers.add_parser("auth", help="Manage Bitwarden authentication and vault sessions")
    auth_sub = auth_parser.add_subparsers(dest="auth_action", required=True)
    
    auth_sub.add_parser("status", help="Get current authentication and vault lock status")
    
    login_pwd = auth_sub.add_parser("login-password", help="Login using Master Password")
    login_pwd.add_argument("--email", required=True, help="Bitwarden account email")
    login_pwd.add_argument("--password", required=True, help="Bitwarden master password")
    login_pwd.add_argument("--code", help="Two-factor authentication code (optional)")
    
    login_api = auth_sub.add_parser("login-apikey", help="Login using API Key")
    login_api.add_argument("--client-id", required=True, help="Bitwarden Client ID")
    login_api.add_argument("--client-secret", required=True, help="Bitwarden Client Secret")
    
    unlock_cmd = auth_sub.add_parser("unlock", help="Unlock vault with master password or PIN")
    unlock_cmd.add_argument("--password", required=True, help="Master password or PIN")
    
    auth_sub.add_parser("lock", help="Lock vault and clear session")
    auth_sub.add_parser("logout", help="Logout from Bitwarden account")
    
    # hook command
    hook_parser = subparsers.add_parser("hook", help="Manage system integration hooks")
    hook_sub = hook_parser.add_subparsers(dest="hook_action", required=True)
    hook_sub.add_parser("install", help="Install system-lock hook into Omarchy hooks directory")
    
    return parser

def main(args: Optional[List[str]] = None) -> int:
    parser = create_parser()
    parsed = parser.parse_args(args)
    
    config_path = Path(parsed.config_path) if parsed.config_path else None
    config_mgr = ConfigManager(config_path=config_path)
    cfg = config_mgr.load()
    
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
        auth_mgr = AuthManager(bw_path=bw_path)
        
        if parsed.auth_action == "status":
            st = auth_mgr.get_status()
            print(json.dumps(asdict(st), indent=2))
            return 0
        elif parsed.auth_action == "login-password":
            res = auth_mgr.login_password(parsed.email, parsed.password, parsed.code)
            print(json.dumps(asdict(res), indent=2))
            return 0 if res.ok else 1
        elif parsed.auth_action == "login-apikey":
            res = auth_mgr.login_apikey(parsed.client_id, parsed.client_secret)
            print(json.dumps(asdict(res), indent=2))
            return 0 if res.ok else 1
        elif parsed.auth_action == "unlock":
            res = auth_mgr.unlock(parsed.password)
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
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
