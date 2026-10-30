"""Breach detection via Have I Been Pwned (HIBP) Passwords API.

Uses the k-anonymity model: only the first 5 hex characters of the SHA-1
hash are sent to the API. The full hash never leaves the device.

API docs: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
"""

import hashlib
import threading
import requests
from PyQt6.QtCore import QObject, pyqtSignal


def check_password_breach(password: str) -> tuple[bool, int]:
    """Check if a password appears in known data breaches.

    Returns:
        (is_breached, breach_count) — True and the number of times seen
        if the password has been found in breaches, else (False, 0).

    Raises:
        requests.RequestException on network errors.
    """
    if not password:
        return False, 0

    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "Cipher-PasswordManager/1.0"},
        timeout=5,
    )
    response.raise_for_status()

    for line in response.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2:
            hash_suffix, count = parts
            if hash_suffix.strip() == suffix:
                try:
                    return True, int(count.strip())
                except ValueError:
                    return True, 1

    return False, 0


class _BreachSignaler(QObject):
    """Qt signal bridge ensuring callbacks execute safely on the GUI thread."""
    finished = pyqtSignal(bool, int)
    error = pyqtSignal(str)


class BreachChecker:
    """Crash-proof async breach checker using daemon worker threads and Qt signal dispatch."""

    def __init__(self):
        self._current_req_id = 0
        self._signaler = _BreachSignaler()

    def check(self, password: str, on_result: callable, on_error: callable):
        """Start an async breach check. Cancels any pending check without thread stalls."""
        self.cancel()

        self._current_req_id += 1
        req_id = self._current_req_id

        self._signaler.finished.connect(on_result)
        self._signaler.error.connect(on_error)

        def worker():
            try:
                is_breached, count = check_password_breach(password)
                if self._current_req_id == req_id:
                    self._signaler.finished.emit(is_breached, count)
            except Exception as e:
                if self._current_req_id == req_id:
                    self._signaler.error.emit(str(e))

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def cancel(self):
        """Invalidate in-flight checks and disconnect listeners immediately."""
        self._current_req_id += 1
        try:
            self._signaler.finished.disconnect()
        except Exception:
            pass
        try:
            self._signaler.error.disconnect()
        except Exception:
            pass
