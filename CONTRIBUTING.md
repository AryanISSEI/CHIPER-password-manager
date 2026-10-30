# Contributing to Cipher

Thank you for your interest in contributing to Cipher Password Manager! As an open-source project, contributions from the community are warmly welcomed.

## Development Setup

1. **Fork and clone** the repository:
   ```bash
   git clone https://github.com/AryanISSEI/CHIPER-password-manager.git
   cd CHIPER-password-manager
   ```

2. **Create a Python virtual environment** (Python 3.10+):
   ```bash
   python -m venv venv
   # Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   # Linux / macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the test suite**:
   ```bash
   pytest -v
   ```

## Pull Request Guidelines

- Ensure all existing and new unit tests pass (`pytest`).
- Maintain zero-knowledge guarantees: never log, store, or transmit unencrypted plaintext passwords or keys.
- Write descriptive commit messages.
- For non-trivial UI or architectural changes, please open an issue first to discuss the proposed change.

## Code of Conduct

Please maintain a respectful, welcoming, and constructive environment for everyone.
