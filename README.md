# Cipher — Minimalist Desktop Password Manager

> **Quiet Security** — A minimalist, zero-knowledge desktop password manager engineered for privacy, cryptographic integrity, and visual calm.

---

For complete architectural documentation, cryptographic specifications, threat models, and component breakdowns, please refer to:
👉 **[PROJECT_OVERVIEW.md](file:///c:/Users/ISSEI/password/PROJECT_OVERVIEW.md)**

---

## Quick Start

### 1. Prerequisites
- Python 3.10+
- Windows 10/11 recommended

### 2. Installation

```powershell
# Clone repository
git clone https://github.com/your-username/cipher.git
cd cipher

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

### 4. Run Tests

```powershell
pytest -v
```

### 5. Google Chrome Extension (Manifest V3)

Cipher integrates directly with Google Chrome for autofill and credential capture:

1. **Register Native Messaging Host**:
   ```powershell
   python extension\native-host\install_native_host.py
   ```
2. **Load Extension in Chrome**:
   - Open Chrome and navigate to `chrome://extensions`
   - Enable **Developer mode** toggle in the top-right corner
   - Click **Load unpacked** and select the `extension` directory
   - Verify the extension ID is `dhmkinmiippfgmcdllobdhkkfccpkaan`

---

## Core Technologies
- **GUI Framework**: PyQt6 (Fusion Style + "Quiet Security" Dark Theme)
- **Encryption**: AES-256-GCM (Per-field authenticated encryption)
- **Key Derivation & Hashing**: Argon2id (100 MB RAM cost, independent KDF salts)
- **Database**: SQLite with SQLAlchemy 2.0 ORM
- **Breach Checking**: Have I Been Pwned API (k-Anonymity model)
- **Packaging**: PyInstaller & Inno Setup 6
