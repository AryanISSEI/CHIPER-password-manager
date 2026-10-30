# Cipher — Minimalist Desktop Password Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Framework: PyQt6](https://img.shields.io/badge/UI-PyQt6-green.svg)](https://www.riverbankcomputing.com/software/pyqt/)
[![Security: Zero--Knowledge](https://img.shields.io/badge/Security-Zero--Knowledge-brightgreen.svg)](SECURITY.md)

> **Quiet Security** — A minimalist, zero-knowledge desktop password manager engineered for privacy, cryptographic integrity, and visual calm.

---

For architectural deep dives, cryptographic specifications, threat models, and component breakdowns, please refer to:
👉 **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)**

---

## Key Features

- **Zero-Knowledge Encryption:** All credentials, usernames, URLs, and notes are encrypted locally with AES-256-GCM. Plaintext never touches disk.
- **Hardware-Resistant Key Derivation:** Argon2id (`t=2`, `m=100MB`, `p=8`) with 16-byte random salts protects master passwords against brute-force attacks.
- **k-Anonymity Breach Auditing:** Integrates with Have I Been Pwned API safely without exposing your passwords.
- **Built-in Browser Extension (Manifest V3):** Secure native messaging IPC for seamless autofill on Chrome and Firefox.
- **Secure Password & Passphrase Generator:** Generate cryptographically secure passwords and memorable diceware passphrases.
- **Zero Telemetry / Local-First:** No analytics, no accounts on external servers, no tracking.

---

## Quick Start

### 1. Prerequisites
- Python 3.10+
- Windows 10/11 (macOS / Linux compatible core)

### 2. Installation

```powershell
# Clone repository
git clone https://github.com/AryanISSEI/CHIPER-password-manager.git
cd CHIPER-password-manager

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Application

```powershell
python main.py
```

### 4. Run Test Suite

```powershell
pytest -v
```

### 5. Browser Extension (Manifest V3)

Cipher integrates directly with Google Chrome and Mozilla Firefox for instant autofill:

1. **Register Native Messaging Host**:
   ```powershell
   python extension\native-host\install_native_host.py
   ```
2. **Load Extension in Chrome**:
   - Open Chrome and navigate to `chrome://extensions`
   - Enable the **Developer mode** toggle in the top-right corner
   - Click **Load unpacked** and select the `extension` directory
   - Verify the extension ID matches `dhmkinmiippfgmcdllobdhkkfccpkaan`

---

## Tech Stack & Cryptography

- **GUI Framework**: PyQt6 (Fusion Style + "Quiet Security" Dark Theme)
- **Encryption**: AES-256-GCM (Per-field authenticated encryption with random nonces)
- **Key Derivation & Hashing**: Argon2id (100 MB RAM cost, independent KDF salts)
- **Database**: SQLite with SQLAlchemy 2.0 ORM
- **Breach Auditing**: Have I Been Pwned API (k-Anonymity model)
- **Packaging**: PyInstaller & Inno Setup 6

---

## Documentation & Policies

- [Project Architecture & Deep Dive](PROJECT_OVERVIEW.md)
- [Security Policy](SECURITY.md)
- [Privacy Policy](PRIVACY.md)
- [Contributing Guidelines](CONTRIBUTING.md)

---

## License

This project is licensed under the [MIT License](LICENSE).
