import json
import os
from pathlib import Path
import pytest
from bitwarden_helper.config import ConfigManager, Config

def test_default_config(tmp_path: Path):
    config_file = tmp_path / "config.json"
    mgr = ConfigManager(config_path=config_file)
    cfg = mgr.load()
    
    assert cfg.server_url == "https://vault.bitwarden.com"
    assert cfg.bw_path == "bw"
    assert cfg.auto_lock_minutes == 15
    assert cfg.clipboard_clear_seconds == 30

def test_custom_config_save_and_load(tmp_path: Path):
    config_file = tmp_path / "config.json"
    mgr = ConfigManager(config_path=config_file)
    
    custom_cfg = Config(
        server_url="https://vault.custom.domain",
        bw_path="/usr/local/bin/bw",
        auto_lock_minutes=30,
        clipboard_clear_seconds=45,
    )
    mgr.save(custom_cfg)
    
    assert config_file.exists()
    loaded_cfg = mgr.load()
    assert loaded_cfg.server_url == "https://vault.custom.domain"
    assert loaded_cfg.bw_path == "/usr/local/bin/bw"
    assert loaded_cfg.auto_lock_minutes == 30
    assert loaded_cfg.clipboard_clear_seconds == 45

def test_partial_config_fallback(tmp_path: Path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"server_url": "https://vaultwarden.local"}))
    
    mgr = ConfigManager(config_path=config_file)
    cfg = mgr.load()
    assert cfg.server_url == "https://vaultwarden.local"
    assert cfg.bw_path == "bw"
    assert cfg.auto_lock_minutes == 15
