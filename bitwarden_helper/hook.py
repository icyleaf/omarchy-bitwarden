import os
from pathlib import Path
import shutil
import subprocess
from typing import Optional

def resolve_helper_executable(hint_path: Optional[str] = None) -> str:
    if hint_path:
        return hint_path
    
    # Check standard install path in Omarchy
    xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    standard_path = Path(xdg_config) / "omarchy" / "plugins" / "icyleaf.bitwarden" / "bin" / "bitwarden-helper"
    if standard_path.exists():
        return str(standard_path.resolve())
    
    # Check project local bin
    local_bin = Path(__file__).resolve().parent.parent / "bin" / "bitwarden-helper"
    if local_bin.exists():
        return str(local_bin.resolve())
        
    return shutil.which("bitwarden-helper") or "bitwarden-helper"

def get_lock_hook_script(helper_path: str) -> str:
    return f"""#!/usr/bin/env bash
# Auto-lock Bitwarden vault on system lock
{helper_path} auth lock >/dev/null 2>&1 || true
"""

def install_lock_hook(helper_path: Optional[str] = None, hooks_base_dir: Optional[Path] = None) -> Path:
    resolved_helper = resolve_helper_executable(helper_path)
    
    if not hooks_base_dir:
        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        hooks_base_dir = Path(xdg_config) / "omarchy" / "hooks"
        
    hook_dest_dir = hooks_base_dir / "system-lock.d"
    hook_dest_dir.mkdir(parents=True, exist_ok=True)
    
    hook_file = hook_dest_dir / "99-bitwarden-lock.sh"
    hook_content = get_lock_hook_script(resolved_helper)
    
    hook_file.write_text(hook_content, encoding="utf-8")
    hook_file.chmod(0o755)
    return hook_file
