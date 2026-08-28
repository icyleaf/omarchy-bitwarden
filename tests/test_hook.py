import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from bitwarden_helper.hook import install_lock_hook, get_lock_hook_script

def test_get_lock_hook_script():
    script = get_lock_hook_script("/custom/path/bitwarden-helper")
    assert "/custom/path/bitwarden-helper" in script
    assert "auth lock" in script

def test_install_lock_hook(tmp_path: Path):
    hooks_dir = tmp_path / "omarchy" / "hooks"
    target_file = install_lock_hook(helper_path="/opt/bin/bitwarden-helper", hooks_base_dir=hooks_dir)
    assert target_file.exists()
    assert os.access(target_file, os.X_OK)
    content = target_file.read_text()
    assert "/opt/bin/bitwarden-helper auth lock" in content
