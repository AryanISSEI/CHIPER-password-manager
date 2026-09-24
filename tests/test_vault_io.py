"""Tests for vault export and import operations.

Tests:
  - Encrypted export → import round-trip
  - CSV export → import round-trip
  - Multi-format CSV import (Bitwarden, Chrome)
  - Corrupt file handling
  - Empty vault export
"""

import os
import csv
import tempfile
import pytest
from services.crypto import generate_vault_key, encrypt_data
from services.vault_io import (
    export_vault_encrypted, import_vault_encrypted,
    export_vault_csv, import_vault_csv,
    _normalize_csv_row,
)
from models import Base
from models.user import User
from models.vault import VaultEntry
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def vault_env(monkeypatch):
    """Set up an isolated in-memory database with a test user and entries."""
    engine = create_engine('sqlite:///:memory:', echo=False)
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    # Monkey-patch the Session used by vault_io and crypto
    monkeypatch.setattr('services.vault_io.Session', TestSession)
    monkeypatch.setattr('models.Session', TestSession)

    vault_key = generate_vault_key()

    # Create a user
    session = TestSession()
    user = User(
        username='testuser',
        password_hash='fake_hash',
        salt='fake_salt',
        kdf_salt='fake_kdf_salt',
        encrypted_vault_key='fake_evk',
        vault_key_nonce='fake_nonce',
    )
    session.add(user)
    session.commit()
    user_id = user.id

    # Add some test entries
    for title, username, password, url in [
        ('GitHub', 'user@github.com', 'GhP@ssw0rd!2024', 'https://github.com'),
        ('Gmail', 'user@gmail.com', 'Gm@il_Secure_99', 'https://mail.google.com'),
        ('AWS', 'admin', 'Amaz0n!Cloud#Key', 'https://console.aws.amazon.com'),
    ]:
        enc_title, n_title = encrypt_data(title, vault_key)
        enc_user, n_user = encrypt_data(username, vault_key)
        enc_pass, n_pass = encrypt_data(password, vault_key)
        enc_url, n_url = encrypt_data(url, vault_key)

        entry = VaultEntry(
            user_id=user_id,
            encrypted_title=enc_title, nonce_title=n_title,
            encrypted_username=enc_user, nonce_username=n_user,
            encrypted_password=enc_pass, nonce_password=n_pass,
            encrypted_url=enc_url, nonce_url=n_url,
            category='login',
        )
        session.add(entry)

    session.commit()
    session.close()

    yield {
        'engine': engine,
        'session_cls': TestSession,
        'vault_key': vault_key,
        'user_id': user_id,
    }

    Base.metadata.drop_all(engine)


class TestEncryptedExportImport:
    """Encrypted .cipher format round-trip tests."""

    def test_roundtrip_with_vault_key(self, vault_env, tmp_path):
        """Export and import using the vault key (no export password)."""
        file_path = str(tmp_path / "backup.cipher")
        vault_key = vault_env['vault_key']
        user_id = vault_env['user_id']

        # Export
        export_vault_encrypted(user_id, vault_key, file_path)
        assert os.path.exists(file_path)
        assert os.path.getsize(file_path) > 28  # salt + nonce + ciphertext

        # Create a second user to import into
        session = vault_env['session_cls']()
        user2 = User(
            username='user2',
            password_hash='h', salt='s', kdf_salt='k',
            encrypted_vault_key='e', vault_key_nonce='n',
        )
        session.add(user2)
        session.commit()
        user2_id = user2.id
        session.close()

        # Import into second user
        count = import_vault_encrypted(user2_id, vault_key, file_path)
        assert count == 3

    def test_roundtrip_with_export_password(self, vault_env, tmp_path):
        """Export with a custom password, import with the same password."""
        file_path = str(tmp_path / "pw_backup.cipher")
        vault_key = vault_env['vault_key']
        user_id = vault_env['user_id']
        export_pw = "ExportP@ssword!123"

        export_vault_encrypted(
            user_id, vault_key, file_path, export_password=export_pw
        )

        session = vault_env['session_cls']()
        user2 = User(
            username='user3',
            password_hash='h', salt='s', kdf_salt='k',
            encrypted_vault_key='e', vault_key_nonce='n',
        )
        session.add(user2)
        session.commit()
        user2_id = user2.id
        session.close()

        count = import_vault_encrypted(
            user2_id, vault_key, file_path, export_password=export_pw
        )
        assert count == 3

    def test_wrong_password_fails(self, vault_env, tmp_path):
        """Import with wrong password should raise ValueError."""
        file_path = str(tmp_path / "wrong_pw.cipher")
        vault_key = vault_env['vault_key']
        user_id = vault_env['user_id']

        export_vault_encrypted(
            user_id, vault_key, file_path, export_password="correct"
        )

        with pytest.raises(ValueError, match="Decryption failed"):
            import_vault_encrypted(
                user_id, vault_key, file_path, export_password="wrong"
            )

    def test_corrupt_file_fails(self, vault_env, tmp_path):
        """Tampered file should fail to import."""
        file_path = str(tmp_path / "corrupt.cipher")

        # Write garbage
        with open(file_path, 'wb') as f:
            f.write(b'\x00' * 100)

        with pytest.raises(ValueError):
            import_vault_encrypted(
                vault_env['user_id'], vault_env['vault_key'], file_path
            )

    def test_too_small_file_fails(self, vault_env, tmp_path):
        """File smaller than header (28 bytes) should fail."""
        file_path = str(tmp_path / "tiny.cipher")
        with open(file_path, 'wb') as f:
            f.write(b'\x00' * 10)

        with pytest.raises(ValueError, match="too small"):
            import_vault_encrypted(
                vault_env['user_id'], vault_env['vault_key'], file_path
            )


class TestCSVExportImport:
    """CSV plaintext format tests."""

    def test_csv_roundtrip(self, vault_env, tmp_path):
        """Export to CSV and re-import."""
        file_path = str(tmp_path / "vault.csv")
        vault_key = vault_env['vault_key']
        user_id = vault_env['user_id']

        export_vault_csv(user_id, vault_key, file_path)
        assert os.path.exists(file_path)

        # Verify CSV contents
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 3
        titles = {r['name'] for r in rows}
        assert 'GitHub' in titles
        assert 'Gmail' in titles
        assert 'AWS' in titles

        # Import into fresh user
        session = vault_env['session_cls']()
        user2 = User(
            username='csv_user',
            password_hash='h', salt='s', kdf_salt='k',
            encrypted_vault_key='e', vault_key_nonce='n',
        )
        session.add(user2)
        session.commit()
        user2_id = user2.id
        session.close()

        count = import_vault_csv(user2_id, vault_key, file_path)
        assert count == 3


class TestCSVNormalization:
    """Test CSV row normalization for various password manager formats."""

    def test_cipher_format(self):
        row = {
            'name': 'Test', 'username': 'user', 'password': 'pw',
            'url': 'https://test.com', 'notes': '', 'category': 'login',
        }
        result = _normalize_csv_row(row)
        assert result['name'] == 'Test'
        assert result['username'] == 'user'
        assert result['password'] == 'pw'

    def test_bitwarden_format(self):
        row = {
            'name': 'Bitwarden Entry',
            'login_username': 'bw_user',
            'login_password': 'bw_pass',
            'login_uri': 'https://bitwarden.com',
            'notes': 'some notes',
        }
        result = _normalize_csv_row(row)
        assert result['name'] == 'Bitwarden Entry'
        assert result['username'] == 'bw_user'
        assert result['password'] == 'bw_pass'
        assert result['url'] == 'https://bitwarden.com'

    def test_chrome_format(self):
        row = {
            'name': 'Chrome Entry',
            'url': 'https://chrome.com',
            'username': 'chrome_user',
            'password': 'chrome_pass',
        }
        result = _normalize_csv_row(row)
        assert result['name'] == 'Chrome Entry'
        assert result['username'] == 'chrome_user'
        assert result['password'] == 'chrome_pass'

    def test_empty_row_returns_empty_password(self):
        row = {'name': '', 'password': ''}
        result = _normalize_csv_row(row)
        assert result['password'] == ''

    def test_invalid_category_defaults_to_login(self):
        row = {'name': 'Test', 'password': 'pw', 'category': 'invalid'}
        result = _normalize_csv_row(row)
        assert result['category'] == 'login'
