from dataclasses import dataclass, asdict
import os
from pathlib import Path
import shutil
import subprocess
from typing import Optional

@dataclass
class HealthStatus:
    installed: bool
    ok: bool
    executable_path: Optional[str] = None
    version: Optional[str] = None
    error: Optional[str] = None

def resolve_executable(bw_path: str) -> Optional[str]:
    # Check if absolute/direct path exists
    candidate = Path(bw_path).expanduser()
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate.resolve())
    
    # Check in PATH
    found = shutil.which(bw_path)
    if found:
        return found
    return None

def check_cli_health(bw_path: str = "bw") -> HealthStatus:
    resolved = resolve_executable(bw_path)
    if not resolved:
        return HealthStatus(
            installed=False,
            ok=False,
            executable_path=None,
            version=None,
            error=f"Bitwarden CLI executable '{bw_path}' not found in PATH or filesystem.",
        )
    
    try:
        res = subprocess.run(
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if res.returncode == 0:
            ver = res.stdout.strip()
            return HealthStatus(
                installed=True,
                ok=True,
                executable_path=resolved,
                version=ver,
                error=None,
            )
        else:
            err = res.stderr.strip() or f"Process returned exit code {res.returncode}"
            return HealthStatus(
                installed=True,
                ok=False,
                executable_path=resolved,
                version=None,
                error=err,
            )
    except Exception as e:
        return HealthStatus(
            installed=True,
            ok=False,
            executable_path=resolved,
            version=None,
            error=f"Failed to execute '{resolved}': {e}",
        )
