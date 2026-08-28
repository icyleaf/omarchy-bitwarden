import shutil
import subprocess
from typing import Optional

SERVICE_NAME = "omarchy-bitwarden"
ACCOUNT_NAME = "session"
LABEL = "Omarchy Bitwarden Session"

class KeyringManager:
    def __init__(self, secret_tool_path: str = "secret-tool"):
        self.secret_tool_path = shutil.which(secret_tool_path) or secret_tool_path

    def store_session(self, session_token: str) -> bool:
        if not session_token:
            return False
        try:
            res = subprocess.run(
                [
                    self.secret_tool_path,
                    "store",
                    f"--label={LABEL}",
                    "service", SERVICE_NAME,
                    "account", ACCOUNT_NAME,
                ],
                input=session_token,
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    def get_session(self) -> Optional[str]:
        try:
            res = subprocess.run(
                [
                    self.secret_tool_path,
                    "lookup",
                    "service", SERVICE_NAME,
                    "account", ACCOUNT_NAME,
                ],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
            return None
        except Exception:
            return None

    def clear_session(self) -> bool:
        try:
            res = subprocess.run(
                [
                    self.secret_tool_path,
                    "clear",
                    "service", SERVICE_NAME,
                    "account", ACCOUNT_NAME,
                ],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False
