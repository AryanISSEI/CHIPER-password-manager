from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from models import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False, index=True)

    # ── Authentication ────────────────────────────────────────────────
    # Argon2id hash of the master password.  Used ONLY for login
    # verification.  The hash embeds its own salt (managed by argon2-cffi).
    password_hash = Column(String(255), nullable=False)

    # Random 32-byte salt used by the Argon2id hasher's embedded salt.
    # Kept for legacy/reference — the actual auth salt is inside password_hash.
    salt = Column(String(64), nullable=False)

    # ── Key Derivation ────────────────────────────────────────────────
    # Separate 32-byte salt used ONLY by the Argon2id KDF to derive the
    # Key Encryption Key (KEK).  This is intentionally independent of
    # the authentication salt so that compromising one does not
    # compromise the other.
    kdf_salt = Column(String(64), nullable=False)

    # ── Wrapped Vault Key ─────────────────────────────────────────────
    # The random 32-byte Vault Encryption Key, encrypted (wrapped) with
    # the KEK using AES-256-GCM.  The vault key can only be recovered
    # by deriving the correct KEK from the master password + kdf_salt.
    encrypted_vault_key = Column(String(128), nullable=False)

    # 12-byte nonce used when wrapping the vault key with the KEK.
    vault_key_nonce = Column(String(24), nullable=False)

    # ── Metadata ──────────────────────────────────────────────────────
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"
