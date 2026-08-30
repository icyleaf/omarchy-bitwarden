from dataclasses import dataclass, asdict
import json
import os
import re
import subprocess
from typing import Optional, Dict, Any

from bitwarden_helper.keyring import KeyringManager
from bitwarden_helper.health import resolve_executable

MAX_AUTH_OUTPUT_BYTES = 5 * 1024 * 1024  # 5MB safe bound for auth responses

def sanitize_auth_error(err_str: Optional[str]) -> str:
    if not err_str:
        return "Authentication operation failed."
    lower = err_str.lower()
    if "invalid" in lower and ("password" in lower or "username" in lower or "email" in lower):
        return "Invalid username, email, or master password."
    if "decryption" in lower or "not the expected type" in lower:
        return "Decryption failed. Incorrect master password."
    if "two-step" in lower or "two-factor" in lower or "code" in lower:
        return "Two-factor authentication required or invalid code."
    if "already logged in" in lower:
        return "Already logged in."
    if "network" in lower or "failed to fetch" in lower or "econnrefused" in lower or "timeout" in lower:
        return "Network error: unable to reach Bitwarden server."
    if "vault is locked" in lower:
        return "Vault is locked."
    
    first_line = err_str.strip().split("\n")[0]
    # Redact long hashes, hex, base64 tokens, or file paths
    redacted = re.sub(r"[A-Za-z0-9+/=_-]{20,}", "[REDACTED]", first_line)
    return redacted[:120].strip()

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
    def __init__(self, bw_path: str = "bw", keyring_mgr: Optional[KeyringManager] = None, max_output_bytes: int = MAX_AUTH_OUTPUT_BYTES):
        self.bw_path = resolve_executable(bw_path) or bw_path
        self.keyring_mgr = keyring_mgr or KeyringManager()
        self.max_output_bytes = max_output_bytes

    def _safe_env(self, session: Optional[str] = None, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = os.environ.copy()
        if session:
            env["BW_SESSION"] = session
        if extra:
            env.update(extra)
        return env

    def verify_session(self, session_token: str) -> bool:
        if not session_token:
            return False
        try:
            # Session token passed via isolated child env, never in argv
            res = subprocess.run(
                [self.bw_path, "sync"],
                capture_output=True,
                text=True,
                env=self._safe_env(session=session_token),
                timeout=10,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    def get_status(self, verify: bool = False) -> AuthStatus:
        session = self.keyring_mgr.get_session()
        try:
            res = subprocess.run(
                [self.bw_path, "status"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout:
                out = res.stdout[:self.max_output_bytes]
                data = json.loads(out)
                status_val = data.get("status", "unauthenticated")
                if session and status_val != "unauthenticated":
                    if verify:
                        if not self.verify_session(session):
                            self.keyring_mgr.clear_session()
                            session = None
                            status_val = "locked"
                        else:
                            status_val = "unlocked"
                    else:
                        status_val = "unlocked"

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
            status="unlocked" if session else "unauthenticated",
            server_url=None,
            last_sync=None,
            user_email=None,
            user_id=None,
            has_session=bool(session),
        )

    def login_password(self, email: str, password: str, code: Optional[str] = None) -> AuthResult:
        cmd = [self.bw_path, "login", email, "--passwordfile", "/proc/self/fd/0", "--raw"]
        input_data = password + "\n"
        if code:
            input_data += code + "\n"
        try:
            res = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
            if res.returncode == 0:
                session = res.stdout.strip()[:self.max_output_bytes]
                if session:
                    self.keyring_mgr.store_session(session)
                return AuthResult(ok=True, status="unlocked", session=session, error=None)
            else:
                raw_err = res.stderr.strip() or res.stdout.strip()
                err = sanitize_auth_error(raw_err)
                return AuthResult(ok=False, status="unauthenticated", session=None, error=err)
        except Exception as e:
            return AuthResult(ok=False, status="unauthenticated", session=None, error=sanitize_auth_error(str(e)))

    def login_apikey(self, client_id: str, client_secret: str) -> AuthResult:
        # Deliver client_id and client_secret exclusively through protected stdin pipe
        # ensuring credentials never touch argv or child process environment
        try:
            res = subprocess.run(
                [self.bw_path, "login", "--apikey"],
                input=f"{client_id}\n{client_secret}\n",
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
            if res.returncode == 0:
                return AuthResult(ok=True, status="locked", session=None, error=None)
            else:
                raw_err = res.stderr.strip() or res.stdout.strip()
                err = sanitize_auth_error(raw_err)
                return AuthResult(ok=False, status="unauthenticated", session=None, error=err)
        except Exception as e:
            return AuthResult(ok=False, status="unauthenticated", session=None, error=sanitize_auth_error(str(e)))

    def unlock(self, password: str) -> AuthResult:
        try:
            res = subprocess.run(
                [self.bw_path, "unlock", "--passwordfile", "/proc/self/fd/0", "--raw"],
                input=password + "\n",
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            session = res.stdout.strip()[:self.max_output_bytes]
            if res.returncode == 0 and session:
                self.keyring_mgr.store_session(session)
                return AuthResult(ok=True, status="unlocked", session=session, error=None)
            else:
                raw_err = res.stderr.strip() or res.stdout.strip()
                err = sanitize_auth_error(raw_err)
                return AuthResult(ok=False, status="locked", session=None, error=err)
        except Exception as e:
            return AuthResult(ok=False, status="locked", session=None, error=sanitize_auth_error(str(e)))

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
