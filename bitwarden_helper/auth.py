from dataclasses import dataclass, asdict
import json
import os
import subprocess
from typing import Optional, Dict, Any

from bitwarden_helper.keyring import KeyringManager
from bitwarden_helper.health import resolve_executable

@dataclass
class AuthStatus:
    status: str  # "unauthenticated" | "locked" | "unlocked"
    server_url: Optional[str] = None
    last_sync: Optional[str] = None
    user_email: Optional[str] = None
    user_id: Optional[str] = None
    has_session: bool = False

@dataclass
class AuthResult:
    ok: bool
    status: Optional[str] = None
    session: Optional[str] = None
    error: Optional[str] = None

class AuthManager:
    def __init__(self, bw_path: str = "bw", keyring_mgr: Optional[KeyringManager] = None):
        self.bw_path = resolve_executable(bw_path) or bw_path
        self.keyring_mgr = keyring_mgr or KeyringManager()

    def verify_session(self, session_token: str) -> bool:
        if not session_token:
            return False
        try:
            # Quick check with session token
            res = subprocess.run(
                [self.bw_path, "sync", "--session", session_token],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            # If session is invalid/expired, bw returns non-zero
            return res.returncode == 0
        except Exception:
            return False

    def get_status(self) -> AuthStatus:
        session = self.keyring_mgr.get_session()
        try:
            res = subprocess.run(
                [self.bw_path, "status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode == 0:
                data = json.loads(res.stdout)
                status_val = data.get("status", "unauthenticated")
                
                # Check session validity
                if session and status_val != "unauthenticated":
                    # Check if session is actually valid
                    is_valid = self.verify_session(session)
                    if is_valid:
                        status_val = "unlocked"
                    else:
                        # Session expired; clear dead token from keyring
                        self.keyring_mgr.clear_session()
                        session = None
                        status_val = "locked"

                return AuthStatus(
                    status=status_val,
                    server_url=data.get("serverUrl"),
                    last_sync=data.get("lastSync"),
                    user_email=data.get("userEmail"),
                    user_id=data.get("userId"),
                    has_session=bool(session),
                )
        except Exception:
            pass

        return AuthStatus(
            status="unauthenticated" if not session else "unlocked",
            server_url=None,
            last_sync=None,
            user_email=None,
            user_id=None,
            has_session=bool(session),
        )

    def login_password(self, email: str, password: str, code: Optional[str] = None) -> AuthResult:
        cmd = [self.bw_path, "login", email, password, "--raw"]
        if code:
            cmd.extend(["--code", code])
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
            if res.returncode == 0:
                session = res.stdout.strip()
                if session:
                    self.keyring_mgr.store_session(session)
                return AuthResult(ok=True, status="unlocked", session=session, error=None)
            else:
                err = res.stderr.strip() or res.stdout.strip() or f"Login failed with code {res.returncode}"
                return AuthResult(ok=False, status="unauthenticated", session=None, error=err)
        except Exception as e:
            return AuthResult(ok=False, status="unauthenticated", session=None, error=str(e))

    def login_apikey(self, client_id: str, client_secret: str) -> AuthResult:
        env = os.environ.copy()
        env["BW_CLIENTID"] = client_id
        env["BW_CLIENTSECRET"] = client_secret
        try:
            res = subprocess.run(
                [self.bw_path, "login", "--apikey"],
                capture_output=True,
                text=True,
                env=env,
                timeout=25,
                check=False,
            )
            if res.returncode == 0:
                return AuthResult(ok=True, status="locked", session=None, error=None)
            else:
                err = res.stderr.strip() or res.stdout.strip() or "API Key login failed."
                return AuthResult(ok=False, status="unauthenticated", session=None, error=err)
        except Exception as e:
            return AuthResult(ok=False, status="unauthenticated", session=None, error=str(e))

    def unlock(self, password: str) -> AuthResult:
        try:
            res = subprocess.run(
                [self.bw_path, "unlock", password, "--raw"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                session = res.stdout.strip()
                self.keyring_mgr.store_session(session)
                return AuthResult(ok=True, status="unlocked", session=session, error=None)
            else:
                err = res.stderr.strip() or "Invalid password / unlock failed."
                return AuthResult(ok=False, status="locked", session=None, error=err)
        except Exception as e:
            return AuthResult(ok=False, status="locked", session=None, error=str(e))

    def lock(self) -> AuthResult:
        self.keyring_mgr.clear_session()
        try:
            subprocess.run(
                [self.bw_path, "lock"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            pass
        return AuthResult(ok=True, status="locked", session=None, error=None)

    def logout(self) -> AuthResult:
        self.keyring_mgr.clear_session()
        try:
            subprocess.run(
                [self.bw_path, "logout"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            pass
        return AuthResult(ok=True, status="unauthenticated", session=None, error=None)
