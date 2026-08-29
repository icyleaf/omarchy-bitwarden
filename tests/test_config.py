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
    assert cfg.max_output_mb == 10
    assert cfg.email == ""
    assert cfg.remember_email is True

def test_custom_config_save_and_load(tmp_path: Path):
    config_file = tmp_path / "config.json"
    mgr = ConfigManager(config_path=config_file)
    
    custom_cfg = Config(
        server_url="https://vault.custom.domain",
        bw_path="/usr/local/bin/bw",
        auto_lock_minutes=30,
        clipboard_clear_seconds=45,
        max_output_mb=50,
        email="user@example.com",
        remember_email=True,
    )
    mgr.save(custom_cfg)
    
    assert config_file.exists()
    loaded_cfg = mgr.load()
    assert loaded_cfg.server_url == "https://vault.custom.domain"
    assert loaded_cfg.bw_path == "/usr/local/bin/bw"
    assert loaded_cfg.auto_lock_minutes == 30
    assert loaded_cfg.clipboard_clear_seconds == 45
    assert loaded_cfg.max_output_mb == 50
    assert loaded_cfg.email == "user@example.com"
    assert loaded_cfg.remember_email is True

def test_partial_config_fallback(tmp_path: Path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"server_url": "https://vaultwarden.local"}))
    
    mgr = ConfigManager(config_path=config_file)
    cfg = mgr.load()
    assert cfg.server_url == "https://vaultwarden.local"
    assert cfg.bw_path == "bw"
    assert cfg.auto_lock_minutes == 15
    assert cfg.max_output_mb == 10
    assert cfg.email == ""
    assert cfg.remember_email is True

def test_config_update_remember_email(tmp_path: Path):
    config_file = tmp_path / "config.json"
    mgr = ConfigManager(config_path=config_file)
    cfg = mgr.load()
    cfg.update(email="alice@corp.com", remember_email=False)
    assert cfg.email == "alice@corp.com"
    assert cfg.remember_email is False
    mgr.save(cfg)
    
    reloaded = mgr.load()
    assert reloaded.email == "alice@corp.com"
    assert reloaded.remember_email is False
