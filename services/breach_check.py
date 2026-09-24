"""Breach detection via Have I Been Pwned (HIBP) Passwords API.

Uses the k-anonymity model: only the first 5 hex characters of the SHA-1
hash are sent to the API. The full hash never leaves the device.

API docs: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
"""

import hashlib
import requests
from PyQt6.QtCore import QObject, QThread, pyqtSignal


def check_password_breach(password: str) -> tuple[bool, int]:
    """Check if a password appears in known data breaches.

    Returns:
        (is_breached, breach_count) — True and the number of times seen
        if the password has been found in breaches, else (False, 0).

    Raises:
        requests.RequestException on network errors.
    """
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
        hash_suffix, count = line.split(":")
        if hash_suffix.strip() == suffix:
            return True, int(count.strip())

    return False, 0


class BreachCheckWorker(QObject):
    """Worker that runs breach check in a background thread."""

    finished = pyqtSignal(bool, int)       # (is_breached, count)
    error = pyqtSignal(str)                # error message

    def __init__(self, password: str):
        super().__init__()
        self._password = password
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        try:
            is_breached, count = check_password_breach(self._password)
            if not self._is_cancelled:
                self.finished.emit(is_breached, count)
        except Exception as e:
            if not self._is_cancelled:
                self.error.emit(str(e))


class BreachChecker:
    """Manages async breach checking with thread lifecycle management."""

    def __init__(self):
        self._thread: QThread | None = None
        self._worker: BreachCheckWorker | None = None

    def check(self, password: str,
              on_result: callable,
              on_error: callable):
        """Start an async breach check, cancelling any pending check."""
        self.cancel()

        self._thread = QThread()
        self._worker = BreachCheckWorker(password)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(on_result)
        self._worker.error.connect(on_error)

        # Proper memory management: let the thread and worker delete themselves
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def cancel(self):
        """Cancel any running breach check gracefully."""
        if self._worker:
            self._worker.cancel()
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait()
