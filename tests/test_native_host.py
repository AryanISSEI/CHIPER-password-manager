"""Tests for Cipher Native Messaging Host.

Tests:
  - Protocol message packing and unpacking (length-prefixed JSON)
  - Domain extraction and fuzzy matching heuristics
  - Status and ping handlers
  - Unlock flow (valid and invalid passwords)
  - URL matching and domain filtering
  - Credential retrieval and decryption
  - Vault search
  - Lock and auto-lock timeout behavior
"""

import io
import time
import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "extension", "native-host")))

from cipher_native_host import (
    read_message,
    send_message,
    extract_domain,
    is_domain_match,
    handle_message,
    NativeHostState,
)
from models import init_db, Session
from models.user import User
from models.vault import VaultEntry
from services.crypto import (
    generate_salt,
    generate_vault_key,
    hash_password,
    derive_kek,
    wrap_vault_key,
    encrypt_data,
)


@pytest.fixture
def test_vault(tmp_path, monkeypatch):
    """Create a temporary test database with a user and test credentials."""
    db_path = str(tmp_path / "test_native_host.db")
    settings_path = str(tmp_path / "settings.json")
    monkeypatch.setattr("config.Config.DATABASE_PATH", db_path)
    monkeypatch.setattr("config.Config.DATABASE_URI", f"sqlite:///{db_path}")
    monkeypatch.setattr("config.Config.SETTINGS_FILE", settings_path)

    # Rebind engine & session
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import models

    test_engine = create_engine(f"sqlite:///{db_path}", echo=False)
    test_session_maker = sessionmaker(bind=test_engine)
    monkeypatch.setattr(models, "engine", test_engine)
    monkeypatch.setattr(models, "Session", test_session_maker)

    init_db()

    # Create user
    password = "MasterPassword123!"
    auth_salt = generate_salt()
    kdf_salt = generate_salt()
    pwd_hash = hash_password(password)
    vault_key = generate_vault_key()
    kek = derive_kek(password, kdf_salt)
    enc_vk, vk_nonce = wrap_vault_key(vault_key, kek)

    session = test_session_maker()
    user = User(
        username="testuser",
        password_hash=pwd_hash,
        salt=auth_salt,
        kdf_salt=kdf_salt,
        encrypted_vault_key=enc_vk,
        vault_key_nonce=vk_nonce,
    )
    session.add(user)
    session.commit()

    # Add credentials
    # 1. GitHub
    enc_title, nonce_title = encrypt_data("GitHub", vault_key)
    enc_user, nonce_user = encrypt_data("octocat@github.com", vault_key)
    enc_pwd, nonce_pwd = encrypt_data("github-secret-pwd", vault_key)
    enc_url, nonce_url = encrypt_data("https://github.com/login", vault_key)

    entry1 = VaultEntry(
        user_id=user.id,
        encrypted_title=enc_title,
        nonce_title=nonce_title,
        encrypted_username=enc_user,
        nonce_username=nonce_user,
        encrypted_password=enc_pwd,
        nonce_password=nonce_pwd,
        encrypted_url=enc_url,
        nonce_url=nonce_url,
        category="login",
        is_favorite=True,
    )

    # 2. Google
    enc_title2, nonce_title2 = encrypt_data("Google Account", vault_key)
    enc_user2, nonce_user2 = encrypt_data("user@gmail.com", vault_key)
    enc_pwd2, nonce_pwd2 = encrypt_data("google-super-pass", vault_key)
    enc_url2, nonce_url2 = encrypt_data("https://accounts.google.com/signin", vault_key)

    entry2 = VaultEntry(
        user_id=user.id,
        encrypted_title=enc_title2,
        nonce_title=nonce_title2,
        encrypted_username=enc_user2,
        nonce_username=nonce_user2,
        encrypted_password=enc_pwd2,
        nonce_password=nonce_pwd2,
        encrypted_url=enc_url2,
        nonce_url=nonce_url2,
        category="login",
    )

    session.add_all([entry1, entry2])
    session.commit()
    entry1_id = entry1.id
    entry2_id = entry2.id
    session.close()

    return {
        "password": password,
        "vault_key": vault_key,
        "entry1_id": entry1_id,
        "entry2_id": entry2_id,
    }


def test_message_read_write_roundtrip():
    """Test reading and writing binary length-prefixed JSON messages."""
    stream = io.BytesIO()
    msg = {"requestId": "req_1", "action": "test", "payload": {"foo": "bar"}}
    send_message(msg, stream)

    stream.seek(0)
    read_back = read_message(stream)
    assert read_back == msg


def test_domain_extraction():
    """Test URL normalization and domain extraction."""
    assert extract_domain("https://github.com/login") == "github.com"
    assert extract_domain("http://www.google.com/search") == "google.com"
    assert extract_domain("accounts.google.com") == "accounts.google.com"
    assert extract_domain("https://login.live.com:443/auth") == "login.live.com"
    assert extract_domain("") == ""


def test_domain_matching():
    """Test domain matching heuristics including subdomains."""
    assert is_domain_match("https://github.com/login", "https://github.com")
    assert is_domain_match("https://accounts.google.com", "google.com")
    assert is_domain_match("https://google.com", "accounts.google.com")
    assert not is_domain_match("https://github.com", "https://gitlab.com")


def test_status_locked_and_ping(test_vault):
    """Test ping and initial locked status."""
    state = NativeHostState()
    ping_resp = handle_message({"requestId": "1", "action": "ping"}, state)
    assert ping_resp["success"] is True
    assert ping_resp["data"]["alive"] is True
    assert ping_resp["data"]["unlocked"] is False

    status_resp = handle_message({"requestId": "2", "action": "status"}, state)
    assert status_resp["success"] is True
    assert status_resp["data"]["unlocked"] is False
    assert status_resp["data"]["username"] is None


def test_unlock_failure(test_vault):
    """Test unlock attempt with wrong master password."""
    state = NativeHostState()
    resp = handle_message(
        {"requestId": "3", "action": "unlock", "payload": {"password": "WrongPassword!"}},
        state,
    )
    assert resp["success"] is False
    assert "Invalid master password" in resp["error"]
    assert state.is_unlocked() is False


def test_unlock_success_and_status(test_vault):
    """Test unlock with correct password and resulting unlocked status."""
    state = NativeHostState()
    resp = handle_message(
        {"requestId": "4", "action": "unlock", "payload": {"password": test_vault["password"]}},
        state,
    )
    assert resp["success"] is True
    assert resp["data"]["unlocked"] is True
    assert resp["data"]["username"] == "testuser"
    assert state.is_unlocked() is True

    status_resp = handle_message({"requestId": "5", "action": "status"}, state)
    assert status_resp["data"]["unlocked"] is True
    assert status_resp["data"]["username"] == "testuser"


def test_get_entries_for_url(test_vault):
    """Test querying matching credentials for an active tab URL."""
    state = NativeHostState()
    # Unlock first
    handle_message(
        {"requestId": "1", "action": "unlock", "payload": {"password": test_vault["password"]}},
        state,
    )

    # Query github
    resp = handle_message(
        {"requestId": "2", "action": "get_entries_for_url", "payload": {"url": "https://github.com/settings"}},
        state,
    )
    assert resp["success"] is True
    matches = resp["data"]
    assert len(matches) == 1
    assert matches[0]["title"] == "GitHub"
    assert matches[0]["username"] == "octocat@github.com"
    # Password should NOT be in the summary list
    assert "password" not in matches[0]


def test_get_credential(test_vault):
    """Test retrieving full decrypted credentials for form filling."""
    state = NativeHostState()
    handle_message(
        {"requestId": "1", "action": "unlock", "payload": {"password": test_vault["password"]}},
        state,
    )

    resp = handle_message(
        {"requestId": "2", "action": "get_credential", "payload": {"entryId": test_vault["entry1_id"]}},
        state,
    )
    assert resp["success"] is True
    cred = resp["data"]
    assert cred["title"] == "GitHub"
    assert cred["username"] == "octocat@github.com"
    assert cred["password"] == "github-secret-pwd"
    assert "github.com" in cred["url"]


def test_search_credentials(test_vault):
    """Test searching credentials in the vault."""
    state = NativeHostState()
    handle_message(
        {"requestId": "1", "action": "unlock", "payload": {"password": test_vault["password"]}},
        state,
    )

    # Search for google
    resp = handle_message(
        {"requestId": "2", "action": "search", "payload": {"query": "google"}},
        state,
    )
    assert resp["success"] is True
    assert len(resp["data"]) == 1
    assert resp["data"][0]["title"] == "Google Account"

    # Search empty string returns all
    resp_all = handle_message(
        {"requestId": "3", "action": "search", "payload": {"query": ""}},
        state,
    )
    assert resp_all["success"] is True
    assert len(resp_all["data"]) == 2


def test_lock_and_autolock(test_vault, monkeypatch):
    """Test manual lock and inactivity auto-lock."""
    state = NativeHostState()
    handle_message(
        {"requestId": "1", "action": "unlock", "payload": {"password": test_vault["password"]}},
        state,
    )
    assert state.is_unlocked() is True

    # Manual lock
    lock_resp = handle_message({"requestId": "2", "action": "lock"}, state)
    assert lock_resp["success"] is True
    assert state.is_unlocked() is False

    # Attempting to search while locked returns error
    search_resp = handle_message({"requestId": "3", "action": "search", "payload": {"query": "git"}}, state)
    assert search_resp["success"] is False
    assert "Vault is locked" in search_resp["error"]

    # Re-unlock and test auto-lock timeout
    handle_message(
        {"requestId": "4", "action": "unlock", "payload": {"password": test_vault["password"]}},
        state,
    )
    assert state.is_unlocked() is True

    # Fast forward time beyond timeout
    monkeypatch.setattr("config.Config.VAULT_LOCK_SECONDS", 1)
    state.last_activity = time.time() - 10
    assert state.is_unlocked() is False


def test_save_entry_create_new(test_vault):
    """Test capturing and saving a new credential from the extension."""
    state = NativeHostState()
    handle_message(
        {"requestId": "1", "action": "unlock", "payload": {"password": test_vault["password"]}},
        state,
    )

    save_resp = handle_message(
        {
            "requestId": "2",
            "action": "save_entry",
            "payload": {
                "title": "Twitter / X",
                "username": "developer@x.com",
                "password": "SuperSecretXPassword!99",
                "url": "https://x.com/login",
            },
        },
        state,
    )
    assert save_resp["success"] is True
    assert save_resp["data"]["action"] == "created"
    new_id = save_resp["data"]["id"]

    # Retrieve and verify it was stored encrypted and can be retrieved
    cred_resp = handle_message(
        {"requestId": "3", "action": "get_credential", "payload": {"entryId": new_id}},
        state,
    )
    assert cred_resp["success"] is True
    assert cred_resp["data"]["title"] == "Twitter / X"
    assert cred_resp["data"]["username"] == "developer@x.com"
    assert cred_resp["data"]["password"] == "SuperSecretXPassword!99"
    assert "x.com" in cred_resp["data"]["url"]


def test_save_entry_update_existing(test_vault):
    """Test that capturing a new password for an existing account updates it."""
    state = NativeHostState()
    handle_message(
        {"requestId": "1", "action": "unlock", "payload": {"password": test_vault["password"]}},
        state,
    )

    # test_vault already has GitHub with username octocat@github.com
    update_resp = handle_message(
        {
            "requestId": "2",
            "action": "save_entry",
            "payload": {
                "title": "GitHub",
                "username": "octocat@github.com",
                "password": "NewUpdatedGitHubPassword2026!",
                "url": "https://github.com/login",
            },
        },
        state,
    )
    assert update_resp["success"] is True
    assert update_resp["data"]["action"] == "updated"
    assert update_resp["data"]["id"] == test_vault["entry1_id"]

    # Retrieve updated credential
    cred_resp = handle_message(
        {"requestId": "3", "action": "get_credential", "payload": {"entryId": test_vault["entry1_id"]}},
        state,
    )
    assert cred_resp["success"] is True
    assert cred_resp["data"]["password"] == "NewUpdatedGitHubPassword2026!"


def test_save_entry_locked_fails(test_vault):
    """Test that save_entry is rejected when vault is locked."""
    state = NativeHostState()
    save_resp = handle_message(
        {
            "requestId": "1",
            "action": "save_entry",
            "payload": {
                "title": "Example",
                "username": "user",
                "password": "pwd",
                "url": "https://example.com",
            },
        },
        state,
    )
    assert save_resp["success"] is False
    assert "Vault is locked" in save_resp["error"]


def test_chrome_native_host_manifest():
    """Verify com.cipher.password_manager.json follows Chrome native messaging requirements."""
    manifest_path = os.path.join(
        os.path.dirname(__file__), "..", "extension", "native-host", "com.cipher.password_manager.json"
    )
    assert os.path.isfile(manifest_path)

    import json
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["name"] == "com.cipher.password_manager"
    assert data["type"] == "stdio"
    assert "allowed_origins" in data
    assert isinstance(data["allowed_origins"], list)
    assert len(data["allowed_origins"]) > 0

    for origin in data["allowed_origins"]:
        assert origin.startswith("chrome-extension://")
        assert origin.endswith("/")
        # Chrome extension ID is 32 characters
        ext_id = origin.replace("chrome-extension://", "").rstrip("/")
        assert len(ext_id) == 32
        assert ext_id.isalpha() and ext_id.islower()


def test_chrome_extension_manifest_v3():
    """Verify extension/manifest.json complies with Google Chrome Manifest V3."""
    manifest_path = os.path.join(
        os.path.dirname(__file__), "..", "extension", "manifest.json"
    )
    assert os.path.isfile(manifest_path)

    import json
    import base64
    import hashlib

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["manifest_version"] == 3
    assert "action" in data
    assert "browser_action" not in data
    if "browser_specific_settings" in data:
        assert "gecko" in data["browser_specific_settings"]
        assert "id" in data["browser_specific_settings"]["gecko"]
    assert (
        data["background"].get("service_worker") == "background.js"
        or data["background"].get("scripts") == ["background.js"]
    )

    # Verify deterministic extension key
    assert "key" in data
    der_bytes = base64.b64decode(data["key"])
    sha = hashlib.sha256(der_bytes).hexdigest()[:32]
    derived_id = "".join(chr(ord("a") + int(c, 16)) for c in sha)
    assert derived_id == "dhmkinmiippfgmcdllobdhkkfccpkaan"

    # Verify PNG icons exist
    ext_dir = os.path.join(os.path.dirname(__file__), "..", "extension")
    for size, icon_rel in data["icons"].items():
        icon_full = os.path.join(ext_dir, icon_rel)
        assert os.path.isfile(icon_full), f"Missing icon: {icon_rel}"
        assert icon_rel.endswith(".png")


def test_install_native_host_helpers(tmp_path, monkeypatch):
    """Test installer helper functions for Google Chrome and Firefox manifest generation."""
    from install_native_host import update_manifest_and_bat, DEFAULT_EXTENSION_ID, FIREFOX_EXTENSION_ID

    temp_manifest = tmp_path / "com.cipher.password_manager.json"
    temp_firefox_manifest = tmp_path / "com.cipher.password_manager.firefox.json"
    temp_bat = tmp_path / "cipher_native_host.bat"

    monkeypatch.setattr("install_native_host.MANIFEST_PATH", str(temp_manifest))
    monkeypatch.setattr("install_native_host.FIREFOX_MANIFEST_PATH", str(temp_firefox_manifest))
    monkeypatch.setattr("install_native_host.BAT_PATH", str(temp_bat))

    # Test default installation
    update_manifest_and_bat()
    assert temp_manifest.exists()
    assert temp_firefox_manifest.exists()
    assert temp_bat.exists()

    import json
    with open(str(temp_manifest), "r", encoding="utf-8") as f:
        data = json.load(f)

    expected_origin = f"chrome-extension://{DEFAULT_EXTENSION_ID}/"
    assert expected_origin in data["allowed_origins"]

    # Test custom extension IDs
    custom_id = "abcdefghijklmnopqrstuvwxyz123456"
    update_manifest_and_bat([custom_id])
    with open(str(temp_manifest), "r", encoding="utf-8") as f:
        data_custom = json.load(f)
    assert f"chrome-extension://{custom_id}/" in data_custom["allowed_origins"]


