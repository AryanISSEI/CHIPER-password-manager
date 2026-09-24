"""Tests for standalone SQLAlchemy models and database integrity."""

import pytest
from models.user import User
from models.vault import VaultEntry
from services.crypto import (
    hash_password, verify_password, generate_salt,
    derive_kek, generate_vault_key, wrap_vault_key, unwrap_vault_key,
    encrypt_data, decrypt_data
)


class TestUserModel:
    def test_create_user(self, db_session):
        master_pw = "SuperSecurePassword123!"
        pw_hash = hash_password(master_pw)
        auth_salt = generate_salt()
        kdf_salt = generate_salt()
        kek = derive_kek(master_pw, kdf_salt)
        vault_key = generate_vault_key()
        enc_vk, vk_nonce = wrap_vault_key(vault_key, kek)

        user = User(
            username="alice",
            password_hash=pw_hash,
            salt=auth_salt,
            kdf_salt=kdf_salt,
            encrypted_vault_key=enc_vk,
            vault_key_nonce=vk_nonce
        )
        db_session.add(user)
        db_session.commit()

        retrieved = db_session.query(User).filter_by(username="alice").first()
        assert retrieved is not None
        assert retrieved.username == "alice"
        assert verify_password(retrieved.password_hash, master_pw) is True

        # Ensure unwrapping works
        rec_kek = derive_kek(master_pw, retrieved.kdf_salt)
        recovered_key = unwrap_vault_key(retrieved.encrypted_vault_key, retrieved.vault_key_nonce, rec_kek)
        assert recovered_key == vault_key


class TestVaultEntryModel:
    def test_create_and_decrypt_entry(self, db_session):
        vault_key = generate_vault_key()

        # Create user
        user = User(
            username="bob",
            password_hash="fake_hash",
            salt="salt1",
            kdf_salt="salt2",
            encrypted_vault_key="fake_vk",
            vault_key_nonce="fake_nonce"
        )
        db_session.add(user)
        db_session.commit()

        # Encrypt fields
        enc_title, n_title = encrypt_data("GitHub Account", vault_key)
        enc_user, n_user = encrypt_data("bob@github.com", vault_key)
        enc_pass, n_pass = encrypt_data("Gh_P@ssw0rd_999!", vault_key)

        entry = VaultEntry(
            user_id=user.id,
            encrypted_title=enc_title, nonce_title=n_title,
            encrypted_username=enc_user, nonce_username=n_user,
            encrypted_password=enc_pass, nonce_password=n_pass,
        )
        db_session.add(entry)
        db_session.commit()

        saved_entry = db_session.query(VaultEntry).filter_by(user_id=user.id).first()
        assert saved_entry is not None
        assert decrypt_data(saved_entry.encrypted_title, saved_entry.nonce_title, vault_key) == "GitHub Account"
        assert decrypt_data(saved_entry.encrypted_username, saved_entry.nonce_username, vault_key) == "bob@github.com"
        assert decrypt_data(saved_entry.encrypted_password, saved_entry.nonce_password, vault_key) == "Gh_P@ssw0rd_999!"

    def test_user_isolation(self, db_session):
        u1 = User(username="u1", password_hash="h1", salt="s1", kdf_salt="k1", encrypted_vault_key="v1", vault_key_nonce="n1")
        u2 = User(username="u2", password_hash="h2", salt="s2", kdf_salt="k2", encrypted_vault_key="v2", vault_key_nonce="n2")
        db_session.add_all([u1, u2])
        db_session.commit()

        e1 = VaultEntry(user_id=u1.id, encrypted_title="t1", nonce_title="n1", encrypted_password="p1", nonce_password="n1")
        db_session.add(e1)
        db_session.commit()

        # u2 should have 0 entries
        u2_entries = db_session.query(VaultEntry).filter_by(user_id=u2.id).all()
        assert len(u2_entries) == 0
