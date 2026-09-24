"""Tests for the cryptographic layer.

These tests verify SECURITY PROPERTIES, not just "does it work":
  - Nonce uniqueness (same plaintext → different ciphertext)
  - GCM authentication tag (tampered data → decryption fails)
  - Key separation (wrong key → decryption fails)
  - KEK wrapping round-trip
  - Empty string handling
"""

import pytest
import base64
from cryptography.exceptions import InvalidTag
from services.crypto import (
    generate_salt, generate_vault_key,
    hash_password, verify_password,
    derive_kek, wrap_vault_key, unwrap_vault_key,
    encrypt_data, decrypt_data,
)


# ── Authentication hashing ────────────────────────────────────────────

class TestPasswordHashing:
    def test_correct_password_verifies(self):
        pw = "SuperSecretPassword123!"
        hashed = hash_password(pw)
        assert verify_password(hashed, pw) is True

    def test_wrong_password_rejected(self):
        hashed = hash_password("CorrectPassword")
        assert verify_password(hashed, "WrongPassword") is False

    def test_hash_is_not_plaintext(self):
        pw = "MyPassword"
        hashed = hash_password(pw)
        assert pw not in hashed


# ── KEK derivation ────────────────────────────────────────────────────

class TestKEKDerivation:
    def test_same_inputs_produce_same_kek(self):
        salt = generate_salt()
        k1 = derive_kek("master", salt)
        k2 = derive_kek("master", salt)
        assert k1 == k2

    def test_different_passwords_produce_different_kek(self):
        salt = generate_salt()
        k1 = derive_kek("password1", salt)
        k2 = derive_kek("password2", salt)
        assert k1 != k2

    def test_different_salts_produce_different_kek(self):
        s1 = generate_salt()
        s2 = generate_salt()
        k1 = derive_kek("master", s1)
        k2 = derive_kek("master", s2)
        assert k1 != k2

    def test_kek_is_32_bytes(self):
        salt = generate_salt()
        kek = derive_kek("master", salt)
        assert len(kek) == 32


# ── Vault key wrapping ────────────────────────────────────────────────

class TestKeyWrapping:
    def test_wrap_unwrap_roundtrip(self):
        kek = derive_kek("master", generate_salt())
        vault_key = generate_vault_key()
        enc_vk, nonce = wrap_vault_key(vault_key, kek)
        recovered = unwrap_vault_key(enc_vk, nonce, kek)
        assert recovered == vault_key

    def test_wrong_kek_fails_unwrap(self):
        salt = generate_salt()
        kek_correct = derive_kek("correct", salt)
        kek_wrong = derive_kek("wrong", salt)
        vault_key = generate_vault_key()
        enc_vk, nonce = wrap_vault_key(vault_key, kek_correct)

        with pytest.raises(InvalidTag):
            unwrap_vault_key(enc_vk, nonce, kek_wrong)

    def test_vault_key_is_32_bytes(self):
        vk = generate_vault_key()
        assert len(vk) == 32


# ── AES-256-GCM encryption ───────────────────────────────────────────

class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        key = generate_vault_key()
        ct, nonce = encrypt_data("hello world", key)
        assert decrypt_data(ct, nonce, key) == "hello world"

    def test_same_plaintext_different_ciphertext(self):
        """Nonce uniqueness: encrypting the same plaintext twice MUST
        produce different ciphertext (because of the random nonce)."""
        key = generate_vault_key()
        ct1, n1 = encrypt_data("identical", key)
        ct2, n2 = encrypt_data("identical", key)
        assert ct1 != ct2  # Different ciphertext
        assert n1 != n2    # Different nonce

    def test_wrong_key_fails(self):
        key1 = generate_vault_key()
        key2 = generate_vault_key()
        ct, nonce = encrypt_data("secret", key1)

        with pytest.raises(InvalidTag):
            decrypt_data(ct, nonce, key2)

    def test_tampered_ciphertext_fails(self):
        """GCM authentication tag detects ciphertext tampering."""
        key = generate_vault_key()
        ct_b64, nonce = encrypt_data("secret", key)

        # Flip a byte in the ciphertext
        ct_bytes = bytearray(base64.b64decode(ct_b64))
        ct_bytes[0] ^= 0xFF
        tampered = base64.b64encode(bytes(ct_bytes)).decode()

        with pytest.raises(InvalidTag):
            decrypt_data(tampered, nonce, key)

    def test_tampered_nonce_fails(self):
        """GCM decryption fails if the nonce is tampered with."""
        key = generate_vault_key()
        ct, nonce_b64 = encrypt_data("secret", key)

        # Flip a byte in the nonce
        nonce_bytes = bytearray(base64.b64decode(nonce_b64))
        nonce_bytes[0] ^= 0xFF
        tampered_nonce = base64.b64encode(bytes(nonce_bytes)).decode()

        with pytest.raises(InvalidTag):
            decrypt_data(ct, tampered_nonce, key)

    def test_empty_string_handling(self):
        key = generate_vault_key()
        ct, nonce = encrypt_data("", key)
        assert ct == ""
        assert nonce == ""
        assert decrypt_data("", "", key) == ""

    def test_ciphertext_is_not_plaintext(self):
        key = generate_vault_key()
        plaintext = "MySecretPassword123!"
        ct_b64, _ = encrypt_data(plaintext, key)
        ct_raw = base64.b64decode(ct_b64)
        assert plaintext.encode() not in ct_raw


# ── Full key hierarchy integration ────────────────────────────────────

class TestKeyHierarchy:
    def test_full_flow(self):
        """Simulates the complete registration → login → encrypt → decrypt flow."""
        master_pw = "MyMasterPassword123!"
        kdf_salt = generate_salt()

        # Registration: derive KEK, generate + wrap vault key
        kek = derive_kek(master_pw, kdf_salt)
        vault_key = generate_vault_key()
        enc_vk, vk_nonce = wrap_vault_key(vault_key, kek)

        # Login: derive KEK again, unwrap vault key
        kek2 = derive_kek(master_pw, kdf_salt)
        recovered_vk = unwrap_vault_key(enc_vk, vk_nonce, kek2)
        assert recovered_vk == vault_key

        # Use vault key to encrypt / decrypt
        ct, ct_nonce = encrypt_data("github_password_123", recovered_vk)
        assert decrypt_data(ct, ct_nonce, recovered_vk) == "github_password_123"

    def test_wrong_master_password_cannot_decrypt_vault(self):
        """The most important security property: wrong master password
        → cannot unwrap vault key → cannot decrypt any credential."""
        master_pw = "Correct"
        kdf_salt = generate_salt()

        kek = derive_kek(master_pw, kdf_salt)
        vault_key = generate_vault_key()
        enc_vk, vk_nonce = wrap_vault_key(vault_key, kek)

        # Encrypt a credential
        ct, ct_nonce = encrypt_data("my_password", vault_key)

        # Attacker tries with wrong master password
        wrong_kek = derive_kek("Wrong", kdf_salt)
        with pytest.raises(InvalidTag):
            unwrap_vault_key(enc_vk, vk_nonce, wrong_kek)


# ── Master password change (vault key re-wrapping) ───────────────────

class TestMasterPasswordChange:
    """Tests the full master password change flow with vault key re-wrapping."""

    def test_rewrap_vault_key_with_new_password(self):
        """After re-wrapping, the new password unlocks the vault and the
        old password does NOT."""
        old_pw = "OldMasterPassword!"
        new_pw = "NewMasterPassword!"

        # Registration: set up with old password
        old_kdf_salt = generate_salt()
        old_kek = derive_kek(old_pw, old_kdf_salt)
        vault_key = generate_vault_key()
        enc_vk, vk_nonce = wrap_vault_key(vault_key, old_kek)

        # Encrypt a credential with the vault key
        ct, ct_nonce = encrypt_data("my_secret_password", vault_key)

        # Password change flow:
        # 1. Derive old KEK → unwrap vault key
        recovered_vk = unwrap_vault_key(enc_vk, vk_nonce, old_kek)
        assert recovered_vk == vault_key

        # 2. Generate new KDF salt
        new_kdf_salt = generate_salt()

        # 3. Derive new KEK
        new_kek = derive_kek(new_pw, new_kdf_salt)

        # 4. Re-wrap vault key
        new_enc_vk, new_vk_nonce = wrap_vault_key(recovered_vk, new_kek)

        # Verification: new password CAN unlock
        verify_kek = derive_kek(new_pw, new_kdf_salt)
        final_vk = unwrap_vault_key(new_enc_vk, new_vk_nonce, verify_kek)
        assert final_vk == vault_key

        # Verification: credential still decrypts
        assert decrypt_data(ct, ct_nonce, final_vk) == "my_secret_password"

        # Verification: OLD password CANNOT unlock with NEW wrapped key
        old_attempt_kek = derive_kek(old_pw, new_kdf_salt)
        with pytest.raises(InvalidTag):
            unwrap_vault_key(new_enc_vk, new_vk_nonce, old_attempt_kek)

        # Verification: old KEK also can't unwrap new wrapped key
        with pytest.raises(InvalidTag):
            unwrap_vault_key(new_enc_vk, new_vk_nonce, old_kek)

    def test_rewrap_preserves_vault_key_identity(self):
        """The vault key bytes are identical before and after re-wrap —
        existing encrypted data remains readable."""
        pw1 = "Password_One_123"
        pw2 = "Password_Two_456"

        salt1 = generate_salt()
        kek1 = derive_kek(pw1, salt1)
        vault_key = generate_vault_key()
        enc_vk1, nonce1 = wrap_vault_key(vault_key, kek1)

        # Encrypt multiple fields with the vault key
        ct1, n1 = encrypt_data("field_one", vault_key)
        ct2, n2 = encrypt_data("field_two", vault_key)

        # Re-wrap with new password
        recovered = unwrap_vault_key(enc_vk1, nonce1, kek1)
        salt2 = generate_salt()
        kek2 = derive_kek(pw2, salt2)
        enc_vk2, nonce2 = wrap_vault_key(recovered, kek2)

        # Unlock with new password
        final_vk = unwrap_vault_key(enc_vk2, nonce2, kek2)

        # All fields still decrypt correctly
        assert decrypt_data(ct1, n1, final_vk) == "field_one"
        assert decrypt_data(ct2, n2, final_vk) == "field_two"

