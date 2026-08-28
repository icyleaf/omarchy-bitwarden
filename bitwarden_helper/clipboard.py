import shutil
import subprocess
import threading
from typing import Optional

class ClipboardManager:
    _active_proc: Optional[subprocess.Popen] = None
    _lock = threading.Lock()

    def __init__(self, wl_copy_path: str = "wl-copy"):
        self.wl_copy_path = shutil.which(wl_copy_path) or wl_copy_path

    def copy(self, text: str, sensitive: bool = False, timeout_seconds: int = 30) -> bool:
        if text is None:
            return False
        try:
            res = subprocess.run(
                [self.wl_copy_path],
                input=text,
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            if res.returncode != 0:
                return False

            if sensitive and timeout_seconds > 0:
                self._schedule_auto_clear(timeout_seconds)

            return True
        except Exception:
            return False

    def _schedule_auto_clear(self, timeout_seconds: int) -> None:
        with self._lock:
            # Terminate any previously pending clear timer
            if self._active_proc and self._active_proc.poll() is None:
                try:
                    self._active_proc.terminate()
                except Exception:
                    pass

            cmd = ["sh", "-c", f"sleep {int(timeout_seconds)} && '{self.wl_copy_path}' --clear >/dev/null 2>&1"]
            try:
                self._active_proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except Exception:
                pass

    def clear(self) -> bool:
        with self._lock:
            if self._active_proc and self._active_proc.poll() is None:
                try:
                    self._active_proc.terminate()
                except Exception:
                    pass
        try:
            res = subprocess.run(
                [self.wl_copy_path, "--clear"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False
