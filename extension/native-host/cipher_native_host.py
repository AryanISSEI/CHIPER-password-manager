"""Cipher — Native Messaging Host for Firefox Extension.

Communicates with the Cipher Firefox extension using standard length-prefixed
JSON messages over stdin/stdout.

Zero-knowledge architecture:
- Evaluates master password locally using Argon2id + AES-256-GCM
- Keeps vault key exclusively in memory with auto-lock timeout
- Decrypts requested credentials only on-demand
"""

import sys
import os
import json
import struct
import time
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import Config
import models
from models.user import User
from models.vault import VaultEntry
from services.crypto import (
    verify_password,
    derive_kek,
    unwrap_vault_key,
    decrypt_data,
    encrypt_data,
)
from datetime import datetime

# Windows binary I/O mode setup
if sys.platform == "win32":
    try:
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    except Exception:
        pass


class NativeHostState:
    """Manages ephemeral in-memory state and auto-lock for the native host."""

    def __init__(self):
        self.vault_key: Optional[bytes] = None
        self.user_id: Optional[int] = None
        self.username: Optional[str] = None
        self.last_activity: float = 0.0

    def touch(self):
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def check_auto_lock(self):
        """Check if inactivity timeout expired and lock if so."""
        if self.vault_key is not None:
            Config.load_settings()
            timeout = getattr(Config, "VAULT_LOCK_SECONDS", 300)
            if timeout > 0 and (time.time() - self.last_activity) > timeout:
                self.lock()

    def is_unlocked(self) -> bool:
        self.check_auto_lock()
        return self.vault_key is not None

    def unlock(self, user: User, vault_key: bytes):
        self.vault_key = vault_key
        self.user_id = user.id
        self.username = user.username
        self.touch()

    def lock(self):
        self.vault_key = None
        self.user_id = None
        self.username = None
        self.last_activity = 0.0


def read_message(stream=None) -> Optional[Dict[str, Any]]:
    """Read a length-prefixed JSON message from the input stream."""
    if stream is None:
        stream = sys.stdin.buffer

    raw_length = stream.read(4)
    if not raw_length or len(raw_length) < 4:
        return None

    message_length = struct.unpack("@I", raw_length)[0]
    raw_message = stream.read(message_length)
    if len(raw_message) < message_length:
        return None

    return json.loads(raw_message.decode("utf-8"))


def send_message(message: Dict[str, Any], stream=None):
    """Write a length-prefixed JSON message to the output stream."""
    if stream is None:
        stream = sys.stdout.buffer

    encoded = json.dumps(message).encode("utf-8")
    stream.write(struct.pack("@I", len(encoded)))
    stream.write(encoded)
    stream.flush()


def extract_domain(url: str) -> str:
    """Extract clean normalized domain from URL."""
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def is_domain_match(entry_url: str, target_url: str) -> bool:
    """Check whether an entry's URL/domain matches the target URL/domain."""
    target_domain = extract_domain(target_url)
    if not target_domain:
        return False

    entry_domain = extract_domain(entry_url)
    if not entry_domain:
        # Fallback: check if target_domain is contained in entry_url
        return target_domain in entry_url.lower()

    # Exact domain match
    if entry_domain == target_domain:
        return True

    # Subdomain match (e.g. login.github.com matches github.com or vice-versa)
    if entry_domain.endswith("." + target_domain) or target_domain.endswith("." + entry_domain):
        return True

    return False


def handle_message(msg: Dict[str, Any], state: NativeHostState) -> Dict[str, Any]:
    """Process a message and return the response."""
    request_id = msg.get("requestId")
    action = msg.get("action")
    payload = msg.get("payload") or {}

    response: Dict[str, Any] = {
        "requestId": request_id,
        "action": action,
        "success": False,
    }

    try:
        if action == "ping":
            response["success"] = True
            response["data"] = {
                "alive": True,
                "unlocked": state.is_unlocked(),
            }
            return response

        if action == "status":
            Config.load_settings()
            unlocked = state.is_unlocked()
            response["success"] = True
            response["data"] = {
                "unlocked": unlocked,
                "username": state.username if unlocked else None,
                "timeout": Config.VAULT_LOCK_SECONDS,
            }
            return response

        if action == "unlock":
            Config.load_settings()
            if not getattr(Config, "NATIVE_HOST_ALLOWED", True):
                response["error"] = "Browser extension access is disabled in Cipher settings."
                return response

            password = payload.get("password", "")
            if not password:
                response["error"] = "Password is required."
                return response

            models.init_db()
            session = models.Session()
            try:
                user = session.query(User).first()
                if not user:
                    response["error"] = "No vault found. Please create an account in Cipher desktop app."
                    return response

                if not verify_password(user.password_hash, password):
                    response["error"] = "Invalid master password."
                    return response

                kek = derive_kek(password, user.kdf_salt)
                vault_key = unwrap_vault_key(user.encrypted_vault_key, user.vault_key_nonce, kek)
                state.unlock(user, vault_key)

                response["success"] = True
                response["data"] = {
                    "unlocked": True,
                    "username": user.username,
                }
                return response
            finally:
                session.close()

        if action == "lock":
            state.lock()
            response["success"] = True
            response["data"] = {"unlocked": False}
            return response

        # The following actions require the vault to be unlocked
        if not state.is_unlocked():
            response["error"] = "Vault is locked. Please unlock using your master password."
            return response

        state.touch()

        if action == "get_entries_for_url":
            target_url = payload.get("url", "")
            if not target_url:
                response["error"] = "URL is required."
                return response

            session = models.Session()
            try:
                entries = session.query(VaultEntry).filter_by(user_id=state.user_id).all()
                matches = []
                for entry in entries:
                    try:
                        dec_url = decrypt_data(entry.encrypted_url, entry.nonce_url, state.vault_key) if entry.encrypted_url else ""
                        dec_title = decrypt_data(entry.encrypted_title, entry.nonce_title, state.vault_key)
                        dec_username = decrypt_data(entry.encrypted_username, entry.nonce_username, state.vault_key) if entry.encrypted_username else ""

                        if is_domain_match(dec_url, target_url) or (dec_title and extract_domain(target_url) in dec_title.lower()):
                            matches.append({
                                "id": entry.id,
                                "title": dec_title,
                                "username": dec_username,
                                "url": dec_url,
                                "category": entry.category,
                                "is_favorite": entry.is_favorite,
                            })
                    except Exception:
                        continue

                response["success"] = True
                response["data"] = matches
                return response
            finally:
                session.close()

        if action == "get_credential":
            entry_id = payload.get("entryId")
            if not entry_id:
                response["error"] = "Entry ID is required."
                return response

            session = models.Session()
            try:
                entry = session.query(VaultEntry).filter_by(id=entry_id, user_id=state.user_id).first()
                if not entry:
                    response["error"] = "Credential entry not found."
                    return response

                dec_title = decrypt_data(entry.encrypted_title, entry.nonce_title, state.vault_key)
                dec_username = decrypt_data(entry.encrypted_username, entry.nonce_username, state.vault_key) if entry.encrypted_username else ""
                dec_password = decrypt_data(entry.encrypted_password, entry.nonce_password, state.vault_key)
                dec_url = decrypt_data(entry.encrypted_url, entry.nonce_url, state.vault_key) if entry.encrypted_url else ""

                entry.last_used_at = datetime.utcnow()
                session.commit()

                response["success"] = True
                response["data"] = {
                    "id": entry.id,
                    "title": dec_title,
                    "username": dec_username,
                    "password": dec_password,
                    "url": dec_url,
                }
                return response
            finally:
                session.close()

        if action == "search":
            query = (payload.get("query") or "").strip().lower()

            session = models.Session()
            try:
                entries = session.query(VaultEntry).filter_by(user_id=state.user_id).all()
                results = []
                for entry in entries:
                    try:
                        dec_title = decrypt_data(entry.encrypted_title, entry.nonce_title, state.vault_key)
                        dec_username = decrypt_data(entry.encrypted_username, entry.nonce_username, state.vault_key) if entry.encrypted_username else ""
                        dec_url = decrypt_data(entry.encrypted_url, entry.nonce_url, state.vault_key) if entry.encrypted_url else ""

                        if not query or query in dec_title.lower() or query in dec_username.lower() or query in dec_url.lower():
                            results.append({
                                "id": entry.id,
                                "title": dec_title,
                                "username": dec_username,
                                "url": dec_url,
                                "category": entry.category,
                                "is_favorite": entry.is_favorite,
                            })
                    except Exception:
                        continue

                response["success"] = True
                response["data"] = results
                return response
            finally:
                session.close()

        if action == "save_entry":
            pwd = payload.get("password", "")
            if not pwd:
                response["error"] = "Password is required."
                return response

            url = payload.get("url", "")
            username = payload.get("username", "")
            title = payload.get("title") or (extract_domain(url) or "Saved Credential")
            category = payload.get("category", "login")

            session = models.Session()
            try:
                # Check for existing entry matching same domain and username
                entries = session.query(VaultEntry).filter_by(user_id=state.user_id).all()
                existing_match = None
                for entry in entries:
                    try:
                        dec_url = decrypt_data(entry.encrypted_url, entry.nonce_url, state.vault_key) if entry.encrypted_url else ""
                        dec_user = decrypt_data(entry.encrypted_username, entry.nonce_username, state.vault_key) if entry.encrypted_username else ""
                        if url and is_domain_match(dec_url, url) and dec_user.strip().lower() == username.strip().lower():
                            existing_match = entry
                            break
                    except Exception:
                        continue

                if existing_match:
                    # Update existing entry's password
                    enc_pwd, nonce_pwd = encrypt_data(pwd, state.vault_key)
                    existing_match.encrypted_password = enc_pwd
                    existing_match.nonce_password = nonce_pwd
                    existing_match.updated_at = datetime.utcnow()
                    session.commit()
                    response["success"] = True
                    response["data"] = {
                        "id": existing_match.id,
                        "action": "updated",
                        "title": title,
                        "username": username,
                    }
                    return response
                else:
                    # Create fresh entry
                    enc_title, nonce_title = encrypt_data(title, state.vault_key)
                    enc_user, nonce_user = encrypt_data(username, state.vault_key) if username else ("", "")
                    enc_pwd, nonce_pwd = encrypt_data(pwd, state.vault_key)
                    enc_url, nonce_url = encrypt_data(url, state.vault_key) if url else ("", "")

                    new_entry = VaultEntry(
                        user_id=state.user_id,
                        encrypted_title=enc_title,
                        nonce_title=nonce_title,
                        encrypted_username=enc_user,
                        nonce_username=nonce_user,
                        encrypted_password=enc_pwd,
                        nonce_password=nonce_pwd,
                        encrypted_url=enc_url,
                        nonce_url=nonce_url,
                        category=category,
                        is_favorite=False,
                    )
                    session.add(new_entry)
                    session.commit()
                    response["success"] = True
                    response["data"] = {
                        "id": new_entry.id,
                        "action": "created",
                        "title": title,
                        "username": username,
                    }
                    return response
            finally:
                session.close()

        response["error"] = f"Unknown action: {action}"
        return response

    except Exception as exc:
        response["error"] = str(exc)
        return response


def main():
    """Main event loop for native messaging communication."""
    state = NativeHostState()
    while True:
        try:
            msg = read_message()
            if msg is None:
                # Browser closed the communication pipe
                break

            response = handle_message(msg, state)
            send_message(response)
        except (KeyboardInterrupt, SystemExit):
            break
        except Exception as err:
            # Fallback error response
            send_message({
                "requestId": None,
                "action": "error",
                "success": False,
                "error": str(err),
            })


if __name__ == "__main__":
    main()
