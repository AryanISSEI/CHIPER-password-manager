import os
import secrets
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import Config

# ──────────────────────────────────────────────────────────────────────
# Argon2id Password Hasher — used ONLY for authentication
# ──────────────────────────────────────────────────────────────────────
ph = PasswordHasher(
    time_cost=Config.ARGON2_TIME_COST,
    memory_cost=Config.ARGON2_MEMORY_COST,
    parallelism=Config.ARGON2_PARALLELISM
)


# ──────────────────────────────────────────────────────────────────────
# Primitives
# ──────────────────────────────────────────────────────────────────────

def generate_salt() -> str:
    """Generates a random 32-byte salt, returned as base64.

    Used for Argon2id operations (authentication hashing and KDF).
    Each user gets TWO independent salts:
      - `salt`     → for the authentication hash
      - `kdf_salt` → for deriving the Key Encryption Key (KEK)
    """
    return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')


def generate_vault_key() -> bytes:
    """Generates a random 32-byte (256-bit) key for AES-256-GCM.

    This key is the actual Vault Encryption Key.  It is generated once
    at registration and NEVER stored in plaintext.  It is wrapped
    (encrypted) by the KEK before being persisted to the database.
    """
    return secrets.token_bytes(32)


# ──────────────────────────────────────────────────────────────────────
# Authentication — Argon2id hash / verify
# ──────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hashes a password using Argon2id for **authentication only**.

    The resulting hash embeds its own random salt (managed by argon2-cffi),
    so it is independent of the KDF salt used for key derivation.
    """
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verifies a candidate password against the stored Argon2id hash."""
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


# ──────────────────────────────────────────────────────────────────────
# Key Derivation — Argon2id KDF → KEK
# ──────────────────────────────────────────────────────────────────────

def derive_kek(master_password: str, kdf_salt_b64: str) -> bytes:
    """Derives a 32-byte Key Encryption Key (KEK) from the master
    password and the user's KDF salt using Argon2id.

    The KEK is used to wrap/unwrap the random Vault Key.
    It is NEVER persisted — it exists only in memory during login.

    Args:
        master_password: The user's plaintext master password.
        kdf_salt_b64:    Base64-encoded 32-byte salt (stored in users.kdf_salt).

    Returns:
        32 raw bytes suitable for use as an AES-256-GCM key.
    """
    salt = base64.b64decode(kdf_salt_b64)
    key = hash_secret_raw(
        secret=master_password.encode('utf-8'),
        salt=salt,
        time_cost=Config.ARGON2_TIME_COST,
        memory_cost=Config.ARGON2_MEMORY_COST,
        parallelism=Config.ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID
    )
    return key


# ──────────────────────────────────────────────────────────────────────
# Key Wrapping — KEK encrypts/decrypts the Vault Key
# ──────────────────────────────────────────────────────────────────────

def wrap_vault_key(vault_key: bytes, kek: bytes) -> tuple[str, str]:
    """Encrypts the random Vault Key with the KEK using AES-256-GCM.

    Returns:
        (encrypted_vault_key_b64, nonce_b64)

    Both values are stored in the users table.  The vault key can only
    be recovered by someone who can reproduce the KEK (i.e. who knows
    the master password).
    """
    aesgcm = AESGCM(kek)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, vault_key, None)
    return (
        base64.b64encode(ciphertext).decode('utf-8'),
        base64.b64encode(nonce).decode('utf-8'),
    )


def unwrap_vault_key(encrypted_vault_key_b64: str, nonce_b64: str, kek: bytes) -> bytes:
    """Decrypts the stored Vault Key using the KEK.

    Raises cryptography.exceptions.InvalidTag if the KEK is wrong
    (i.e. wrong master password), which also detects tampering.
    """
    aesgcm = AESGCM(kek)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(encrypted_vault_key_b64)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ──────────────────────────────────────────────────────────────────────
# Vault Encryption — AES-256-GCM per credential field
# ──────────────────────────────────────────────────────────────────────

def encrypt_data(plaintext: str, key: bytes) -> tuple[str, str]:
    """Encrypts a plaintext string using AES-256-GCM.

    A fresh 12-byte nonce is generated for EVERY call.  AES-GCM nonces
    must NEVER be reused with the same key — using `secrets.token_bytes`
    with 96-bit nonces gives a negligible collision probability for
    the volumes this application handles.

    Returns:
        (ciphertext_b64, nonce_b64)

    The ciphertext includes the 16-byte GCM authentication tag, so
    any tampering with ciphertext or nonce will cause decryption to
    raise `InvalidTag`.
    """
    if not plaintext:
        return "", ""

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return (
        base64.b64encode(ciphertext).decode('utf-8'),
        base64.b64encode(nonce).decode('utf-8'),
    )


def decrypt_data(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
    """Decrypts a base64-encoded AES-256-GCM ciphertext.

    Raises `InvalidTag` if:
      - The key is wrong
      - The ciphertext has been tampered with
      - The nonce has been tampered with
    """
    if not ciphertext_b64:
        return ""

    aesgcm = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')
