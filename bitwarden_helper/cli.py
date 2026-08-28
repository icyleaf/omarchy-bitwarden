import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import Optional, List

from bitwarden_helper.config import ConfigManager, Config
from bitwarden_helper.health import check_cli_health

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
    
    return parser

def main(args: Optional[List[str]] = None) -> int:
    parser = create_parser()
    parsed = parser.parse_args(args)
    
    config_path = Path(parsed.config_path) if parsed.config_path else None
    config_mgr = ConfigManager(config_path=config_path)
    
    if parsed.command == "config":
        if parsed.config_action == "get":
            cfg = config_mgr.load()
            print(json.dumps(asdict(cfg), indent=2))
            return 0
        elif parsed.config_action == "set":
            cfg = config_mgr.load()
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
        cfg = config_mgr.load()
        bw_path = parsed.bw_path or cfg.bw_path
        status = check_cli_health(bw_path)
        print(json.dumps(asdict(status), indent=2))
        return 0 if status.ok else 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
