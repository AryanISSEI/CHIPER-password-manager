"""Vault data export and import for Cipher.

Supports two formats:
  - Encrypted (.cipher): AES-256-GCM encrypted JSON blob with Argon2id KDF
  - CSV (.csv): Plaintext for migration to/from other password managers

The encrypted format uses a user-provided export password (independent of
the master password) to derive a one-time encryption key via Argon2id.
"""

import csv
import json
import io
import secrets
import base64
from datetime import datetime

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models import Session
from models.vault import VaultEntry
from services.crypto import encrypt_data, decrypt_data


# ── Encrypted Export / Import (.cipher) ──────────────────────────────

CIPHER_FILE_VERSION = 1
EXPORT_ARGON2_TIME_COST = 3
EXPORT_ARGON2_MEMORY_COST = 65536  # 64 MB — lighter than vault KDF
EXPORT_ARGON2_PARALLELISM = 4


def _derive_export_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from an export password using Argon2id."""
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=EXPORT_ARGON2_TIME_COST,
        memory_cost=EXPORT_ARGON2_MEMORY_COST,
        parallelism=EXPORT_ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )


def export_vault_encrypted(user_id: int, vault_key: bytes,
                           file_path: str,
                           export_password: str | None = None) -> None:
    """Export all vault entries to an encrypted .cipher file.

    If no export_password is provided, the vault key is used directly
    (the file is portable only if the recipient has the same vault key).

    File format:
        16 bytes: salt
        12 bytes: nonce
        remaining: AES-256-GCM ciphertext of JSON payload
    """
    entries_data = _load_all_entries(user_id, vault_key)

    payload = json.dumps({
        'version': CIPHER_FILE_VERSION,
        'exported_at': datetime.utcnow().isoformat(),
        'entries': entries_data,
    }, ensure_ascii=False).encode('utf-8')

    # Derive encryption key
    salt = secrets.token_bytes(16)
    if export_password:
        key = _derive_export_key(export_password, salt)
    else:
        key = vault_key[:32]

    # Encrypt
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload, None)

    with open(file_path, 'wb') as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)


def import_vault_encrypted(user_id: int, vault_key: bytes,
                           file_path: str,
                           export_password: str | None = None) -> int:
    """Import vault entries from an encrypted .cipher file.

    Returns the number of entries imported.
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    if len(data) < 28:
        raise ValueError("File is too small to be a valid .cipher export.")

    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]

    # Derive decryption key
    if export_password:
        key = _derive_export_key(export_password, salt)
    else:
        key = vault_key[:32]

    # Decrypt
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError(
            "Decryption failed. Wrong password or corrupted file."
        )

    payload = json.loads(plaintext.decode('utf-8'))
    entries = payload.get('entries', [])

    return _insert_entries(user_id, vault_key, entries)


# ── CSV Export / Import ──────────────────────────────────────────────

CSV_FIELDS = ['name', 'username', 'password', 'url', 'notes', 'category']


def export_vault_csv(user_id: int, vault_key: bytes,
                     file_path: str) -> None:
    """Export all vault entries to a plaintext CSV file.

    WARNING: Passwords are stored in plain text.
    """
    entries_data = _load_all_entries(user_id, vault_key)

    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS,
                                extrasaction='ignore')
        writer.writeheader()
        for entry in entries_data:
            writer.writerow(entry)


def import_vault_csv(user_id: int, vault_key: bytes,
                     file_path: str) -> int:
    """Import vault entries from a CSV file.

    Supports Cipher's own CSV format and common formats from:
      - Bitwarden (name, login_username, login_password, login_uri, notes)
      - Chrome (name, url, username, password)
      - Firefox (url, username, password)

    Returns the number of entries imported.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Detect format and normalize field names
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is None:
        raise ValueError("CSV file appears to be empty.")

    entries = []
    for row in reader:
        entry = _normalize_csv_row(row)
        if entry and entry.get('name') and entry.get('password'):
            entries.append(entry)

    if not entries:
        raise ValueError("No valid entries found in CSV file.")

    return _insert_entries(user_id, vault_key, entries)


def _normalize_csv_row(row: dict) -> dict:
    """Normalize CSV row from various password manager formats."""
    # Lowercase all keys for flexible matching
    lrow = {k.lower().strip(): v for k, v in row.items() if v}

    name = (
        lrow.get('name')
        or lrow.get('title')
        or lrow.get('login_name')
        or lrow.get('url', '')  # Firefox export only has url
    )
    username = (
        lrow.get('username')
        or lrow.get('login_username')
        or lrow.get('user')
        or ''
    )
    password = (
        lrow.get('password')
        or lrow.get('login_password')
        or ''
    )
    url = (
        lrow.get('url')
        or lrow.get('login_uri')
        or lrow.get('website')
        or ''
    )
    notes = (
        lrow.get('notes')
        or lrow.get('extra')
        or ''
    )
    category = lrow.get('category', 'login')
    if category not in ('login', 'card', 'note', 'identity'):
        category = 'login'

    return {
        'name': name,
        'username': username,
        'password': password,
        'url': url,
        'notes': notes,
        'category': category,
    }


# ── Shared Helpers ───────────────────────────────────────────────────

def _load_all_entries(user_id: int, vault_key: bytes) -> list[dict]:
    """Load and decrypt all vault entries for a user."""
    results = []

    with Session() as session:
        entries = (
            session.query(VaultEntry)
            .filter_by(user_id=user_id)
            .order_by(VaultEntry.created_at.desc())
            .all()
        )

        for e in entries:
            try:
                title = decrypt_data(
                    e.encrypted_title, e.nonce_title, vault_key
                )
                username = (
                    decrypt_data(
                        e.encrypted_username, e.nonce_username, vault_key
                    )
                    if e.encrypted_username else ""
                )
                password = decrypt_data(
                    e.encrypted_password, e.nonce_password, vault_key
                )
                url = (
                    decrypt_data(
                        e.encrypted_url, e.nonce_url, vault_key
                    )
                    if e.encrypted_url else ""
                )
                notes = (
                    decrypt_data(
                        e.encrypted_notes, e.nonce_notes, vault_key
                    )
                    if e.encrypted_notes else ""
                )

                results.append({
                    'name': title,
                    'username': username,
                    'password': password,
                    'url': url,
                    'notes': notes,
                    'category': getattr(e, 'category', 'login') or 'login',
                })
            except Exception:
                pass  # Skip entries that can't be decrypted

    return results


def _insert_entries(user_id: int, vault_key: bytes,
                    entries: list[dict]) -> int:
    """Encrypt and insert entries into the vault. Returns count inserted."""
    count = 0

    with Session() as session:
        for entry in entries:
            name = entry.get('name', '')
            username = entry.get('username', '')
            password = entry.get('password', '')
            url = entry.get('url', '')
            notes = entry.get('notes', '')
            category = entry.get('category', 'login')

            if not name or not password:
                continue

            enc_title, n_title = encrypt_data(name, vault_key)
            enc_user, n_user = (
                encrypt_data(username, vault_key)
                if username else (None, None)
            )
            enc_pass, n_pass = encrypt_data(password, vault_key)
            enc_url, n_url = (
                encrypt_data(url, vault_key)
                if url else (None, None)
            )
            enc_notes, n_notes = (
                encrypt_data(notes, vault_key)
                if notes else (None, None)
            )

            new_entry = VaultEntry(
                user_id=user_id,
                encrypted_title=enc_title, nonce_title=n_title,
                encrypted_username=enc_user, nonce_username=n_user,
                encrypted_password=enc_pass, nonce_password=n_pass,
                encrypted_url=enc_url, nonce_url=n_url,
                encrypted_notes=enc_notes, nonce_notes=n_notes,
                category=category,
            )
            session.add(new_entry)
            count += 1

        session.commit()

    return count
