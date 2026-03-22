# Security Overview

## Features
- 🔐 AES-256 encryption with rotating keys
- 🛡️ Rate limiting, IP ban, CSRF, JWT, HTTPS enforcement
- 🧠 ML-based threat detection with VirusTotal integration
- 🧪 Auto-tests + security checks (OWASP, Bandit)
- ☁️ S3/Cloud backup + restore system

## Encryption Loop
System encrypts sensitive user data using looped AES encryption with key rotation every X days.

## Key Protection
Keys are stored with environment isolation and managed through `key_rotation_scheduler.py`.

## Dashboard Access
Only admin users with MFA enabled may access full statistics, threat reports and system logs.