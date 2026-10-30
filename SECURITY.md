# Security Policy

## Security Model & Zero-Knowledge Architecture

Cipher is designed as a **local-first, zero-knowledge** password manager. All vault entries and sensitive secrets are encrypted locally on the device prior to database storage:

- **Key Derivation:** Argon2id (`t=2`, `m=100MB`, `p=8`) with unique per-user 16-byte cryptographically secure salts.
- **Symmetric Encryption:** AES-256-GCM authenticated encryption with per-field random 12-byte nonces.
- **Zero-Knowledge Principle:** Master passwords and unwrapped vault encryption keys never leave volatile memory and are never written to disk or transmitted over the network.
- **Breach Auditing:** Checks password breaches against the Have I Been Pwned API using a *k-Anonymity* model (only the first 5 characters of the SHA-1 hash prefix are sent).

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Security is paramount for a password manager. If you discover a potential vulnerability or security flaw in Cipher, please report it responsibly:

1. **Do NOT open a public GitHub issue** describing the security vulnerability.
2. Please report the issue privately using **GitHub's Private Vulnerability Reporting** feature via the **Security** tab of the repository, or by contacting the project maintainer directly.
3. Include detailed steps to reproduce the issue, proof of concept (if applicable), and your assessment of the impact.

We will acknowledge receipt of your report within 48 hours and work on a prompt resolution.
