"""Comprehensive integration test for user registration, login, and entry creation/editing.

Validates that user and password entry flows execute without crashes across all categories.
"""

import json
import pytest
import models
from models import init_db
from models.user import User
from models.vault import VaultEntry
from services.crypto import (
    generate_salt,
    generate_vault_key,
    hash_password,
    verify_password,
    derive_kek,
    wrap_vault_key,
    unwrap_vault_key,
    encrypt_data,
    decrypt_data,
)


@pytest.fixture
def isolated_vault(tmp_path, monkeypatch):
    """Provide an isolated database and settings environment."""
    db_path = str(tmp_path / "test_flow.db")
    settings_path = str(tmp_path / "settings.json")
    monkeypatch.setattr("config.Config.DATABASE_PATH", db_path)
    monkeypatch.setattr("config.Config.DATABASE_URI", f"sqlite:///{db_path}")
    monkeypatch.setattr("config.Config.SETTINGS_FILE", settings_path)

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import models

    test_engine = create_engine(f"sqlite:///{db_path}", echo=False)
    test_session_maker = sessionmaker(bind=test_engine)
    monkeypatch.setattr(models, "engine", test_engine)
    monkeypatch.setattr(models, "Session", test_session_maker)

    init_db()
    return {"session_maker": test_session_maker}


def test_user_registration_and_login_flow(isolated_vault):
    """Verify that registering a new user and logging in succeeds without crash."""
    username = "new_secure_user"
    password = "SuperSecretMasterPassword123!"

    # 1. Hashing & Key derivation
    pwd_hash = hash_password(password)
    auth_salt = generate_salt()
    kdf_salt = generate_salt()
    kek = derive_kek(password, kdf_salt)
    vault_key = generate_vault_key()
    enc_vk, vk_nonce = wrap_vault_key(vault_key, kek)

    # 2. Database save
    with models.Session() as session:
        user = User(
            username=username,
            password_hash=pwd_hash,
            salt=auth_salt,
            kdf_salt=kdf_salt,
            encrypted_vault_key=enc_vk,
            vault_key_nonce=vk_nonce,
        )
        session.add(user)
        session.commit()
        user_id = user.id

    # 3. Simulate Login
    with models.Session() as session:
        queried_user = session.query(User).filter_by(username=username).first()
        assert queried_user is not None
        assert verify_password(queried_user.password_hash, password) is True

        # Derive KEK and unwrap vault key
        login_kek = derive_kek(password, queried_user.kdf_salt)
        recovered_vk = unwrap_vault_key(
            queried_user.encrypted_vault_key,
            queried_user.vault_key_nonce,
            login_kek,
        )
        assert recovered_vk == vault_key


def test_add_and_load_entries_all_categories(isolated_vault):
    """Verify adding Login, Card, Secure Note, and Identity entries without crashing."""
    vault_key = generate_vault_key()
    user_id = 1

    # Category 1: Login
    enc_title, n_title = encrypt_data("GitHub", vault_key)
    enc_user, n_user = encrypt_data("octocat", vault_key)
    enc_pass, n_pass = encrypt_data("git-secret-1234", vault_key)
    enc_url, n_url = encrypt_data("https://github.com", vault_key)
    notes_json = json.dumps({"notes": "Developer token included"})
    enc_notes, n_notes = encrypt_data(notes_json, vault_key)

    with models.Session() as session:
        entry1 = VaultEntry(
            user_id=user_id,
            encrypted_title=enc_title, nonce_title=n_title,
            encrypted_username=enc_user, nonce_username=n_user,
            encrypted_password=enc_pass, nonce_password=n_pass,
            encrypted_url=enc_url, nonce_url=n_url,
            encrypted_notes=enc_notes, nonce_notes=n_notes,
            category="login",
        )
        session.add(entry1)
        session.commit()

    # Category 2: Card
    enc_title, n_title = encrypt_data("Visa Primary", vault_key)
    enc_user, n_user = encrypt_data("John Doe", vault_key)
    enc_pass, n_pass = encrypt_data("4111222233334444", vault_key)
    card_notes = json.dumps({"exp": "12/28", "cvv": "123", "pin": "9999", "notes": ""})
    enc_notes, n_notes = encrypt_data(card_notes, vault_key)

    with models.Session() as session:
        entry2 = VaultEntry(
            user_id=user_id,
            encrypted_title=enc_title, nonce_title=n_title,
            encrypted_username=enc_user, nonce_username=n_user,
            encrypted_password=enc_pass, nonce_password=n_pass,
            encrypted_notes=enc_notes, nonce_notes=n_notes,
            category="card",
        )
        session.add(entry2)
        session.commit()

    # Category 3: Secure Note (empty password test)
    enc_title, n_title = encrypt_data("Server Recovery Keys", vault_key)
    enc_pass, n_pass = encrypt_data("", vault_key)
    note_notes = json.dumps({"notes": "Key1: AAAA-BBBB-CCCC\nKey2: DDDD-EEEE-FFFF"})
    enc_notes, n_notes = encrypt_data(note_notes, vault_key)

    with models.Session() as session:
        entry3 = VaultEntry(
            user_id=user_id,
            encrypted_title=enc_title, nonce_title=n_title,
            encrypted_password=enc_pass, nonce_password=n_pass,
            encrypted_notes=enc_notes, nonce_notes=n_notes,
            category="note",
        )
        session.add(entry3)
        session.commit()

    # Category 4: Identity
    enc_title, n_title = encrypt_data("Passport Profile", vault_key)
    enc_user, n_user = encrypt_data("Jane Doe", vault_key)
    enc_pass, n_pass = encrypt_data("123-45-6789", vault_key)
    id_notes = json.dumps({
        "email": "jane@example.com",
        "phone": "+1-555-0100",
        "address": "123 Main St, Springfield",
        "notes": "Home address verified",
    })
    enc_notes, n_notes = encrypt_data(id_notes, vault_key)

    with models.Session() as session:
        entry4 = VaultEntry(
            user_id=user_id,
            encrypted_title=enc_title, nonce_title=n_title,
            encrypted_username=enc_user, nonce_username=n_user,
            encrypted_password=enc_pass, nonce_password=n_pass,
            encrypted_notes=enc_notes, nonce_notes=n_notes,
            category="identity",
        )
        session.add(entry4)
        session.commit()

    # Verify retrieval and decrypting all entries
    with models.Session() as session:
        entries = session.query(VaultEntry).filter_by(user_id=user_id).all()
        assert len(entries) == 4

        for e in entries:
            dec_title = decrypt_data(e.encrypted_title, e.nonce_title, vault_key)
            assert len(dec_title) > 0
            if e.encrypted_password:
                dec_pwd = decrypt_data(e.encrypted_password, e.nonce_password, vault_key)
                if e.category == "note":
                    assert dec_pwd == ""
                elif e.category == "card":
                    assert dec_pwd == "4111222233334444"
