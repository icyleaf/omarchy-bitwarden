from dataclasses import dataclass, asdict
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any

DEFAULT_SERVER_URL = "https://vault.bitwarden.com"
DEFAULT_BW_PATH = "bw"
DEFAULT_AUTO_LOCK_MINUTES = 15
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30

@dataclass
class Config:
    server_url: str = DEFAULT_SERVER_URL
    bw_path: str = DEFAULT_BW_PATH
    auto_lock_minutes: int = DEFAULT_AUTO_LOCK_MINUTES
    clipboard_clear_seconds: int = DEFAULT_CLIPBOARD_CLEAR_SECONDS

    def update(self, **kwargs: Any) -> "Config":
        for key, value in kwargs.items():
            if value is not None and hasattr(self, key):
                field_type = type(getattr(self, key))
                setattr(self, key, field_type(value))
        return self

class ConfigManager:
    def __init__(self, config_path: Optional[Path] = None):
        if config_path:
            self.config_path = Path(config_path)
        else:
            xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
            self.config_path = Path(xdg_config) / "omarchy" / "plugins" / "icyleaf.bitwarden" / "config.json"

    def load(self) -> Config:
        if not self.config_path.exists():
            return Config()
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return Config(
                server_url=data.get("server_url", DEFAULT_SERVER_URL),
                bw_path=data.get("bw_path", DEFAULT_BW_PATH),
                auto_lock_minutes=int(data.get("auto_lock_minutes", DEFAULT_AUTO_LOCK_MINUTES)),
                clipboard_clear_seconds=int(data.get("clipboard_clear_seconds", DEFAULT_CLIPBOARD_CLEAR_SECONDS)),
            )
        except Exception:
            return Config()

    def save(self, config: Config) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(asdict(config), f, indent=2)
