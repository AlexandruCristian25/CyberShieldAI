# CyberShield AI

## Intelligent Cybersecurity Protection for Modern Infrastructure

CyberShield AI is a **modular cybersecurity platform** designed to help organizations monitor, protect, and manage their digital infrastructure against modern cyber threats.

Built with a strong focus on **security, transparency, and automation**, CyberShield AI combines **AI-powered assistance**, **encrypted backups**, **audit logging**, **2FA authentication**, **file scanning capabilities**, and **WAF integrations** into a unified security platform.

> **Protect smarter. Respond faster. Stay secure.**

---

## Overview

Modern organizations face increasingly sophisticated cyber threats, including **ransomware**, **credential attacks**, **malware uploads**, **infrastructure exploitation**, and **unauthorized access attempts**.

CyberShield AI provides a centralized platform that enables:

* Real-time security monitoring
* Secure authentication & access control
* Advanced audit logging
* Encrypted backup & recovery
* AI-assisted security insights
* Web Application Firewall (WAF) integration
* File upload scanning workflows
* Email alerting & security notifications
* Encryption key rotation support

The platform is designed to be **lightweight, extensible, and easy to integrate into existing infrastructure**.

---

## Key Features

### Secure Authentication & Access Control

CyberShield AI includes a **JWT-based authentication system** with **role-based access control (RBAC)** and **two-factor authentication (2FA)** support.

#### Features

* Secure login and session handling
* JWT access tokens
* Role-based permissions (**Admin / Analyst / Auditor**)
* Token expiration and refresh mechanisms
* Brute-force protection
* 2FA using **PyOTP**

---

### Advanced Audit Logging

CyberShield AI provides a **comprehensive audit logging system** designed for transparency, compliance, and forensic analysis.

#### The system tracks

* User actions
* Login attempts
* Administrative changes
* File operations
* Security events
* System activity

#### Additional capabilities

* Audit export tools
* Backup and decryption utilities
* Audit viewer interface
* Incident investigation support

---

### Encrypted Backup & Recovery

CyberShield AI includes **AES-based encryption** for protecting sensitive backups and exported security data.

#### Features

* Encrypted database backups
* Secure backup storage
* Key management support
* Fast recovery procedures
* Ransomware resilience
* Backup integrity protection

---

### AI Security Assistant

The integrated AI assistant helps security teams interpret system events and identify potential risks.

#### Capabilities

* Contextual security explanations
* Threat awareness recommendations
* Incident response guidance
* Security posture insights
* Operational assistance for analysts

---

### File Security & Upload Scanning

CyberShield AI includes a dedicated **file-scan-log application** for managing uploaded files and tracking scanning activity.

#### Features

* File upload logging
* Scan tracking workflows
* User-scoped scan management
* Executive security reporting support
* React + Vite frontend for security dashboards

---

### WAF Integration

CyberShield AI supports **Cloudflare Web Application Firewall templates** and defensive filtering rules.

#### Protection against

* SQL Injection (**SQLi**)
* Cross-Site Scripting (**XSS**)
* Automated bot attacks
* Suspicious traffic patterns
* Malicious request payloads

---

### Email Alerts & Notifications

Built-in email alerting allows security teams to receive notifications for important events.

#### Examples

* Failed login attempts
* Suspicious activity detection
* Administrative changes
* Backup failures
* Security scan alerts

---

### Encryption Key Rotation

CyberShield AI includes a **key rotation scheduler** for improving long-term cryptographic hygiene.

#### Benefits

* Reduced key exposure risk
* Better compliance alignment
* Automated rotation workflows
* Improved operational security

---

## Technology Stack

### Backend

* **Python**
* **Flask**
* **SQLAlchemy ORM**

### Frontend

* **React 18**
* **Vite**
* **TypeScript**
* **Tailwind CSS**

### Security

* **AES Encryption**
* **JWT Authentication**
* **PyOTP (2FA)**
* **Bcrypt Password Hashing**
* **Secure Token Handling**

### Database Support

* **SQLite** (default)
* **PostgreSQL** (via `psycopg2-binary`)

### Cloud & Infrastructure

* **AWS S3 support** (`boto3`)
* Environment-based configuration (`.env`)
* Modular architecture
* CI/CD security workflow support

---

## Project Structure

```text
CyberShieldAI/
├── backend/
│   ├── app.py
│   ├── audit_log.py
│   ├── backup.py
│   ├── database/
│   ├── uploads/
│   └── utils/
├── crypto/
├── admin/
├── dashboard/
├── audit_backups/
├── file-scan-log-app/
├── requirements.txt
├── package.json
└── .github/workflows/
```

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/AlexandruCristian25/CyberShieldAI.git
cd CyberShieldAI
```

---

### 2. Create a Virtual Environment

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

---

### 3. Install Backend Dependencies

```bash
pip install -r requirements.txt
```

The project currently uses:

```text
flask
bcrypt
pyotp
psycopg2-binary
boto3
python-dotenv
```

#### Recommended additional packages

```bash
pip install sqlalchemy pyjwt cryptography flask-cors
```

---

### 4. Configure Environment Variables

Create the configuration file:

#### Linux / macOS

```bash
cp .env.example .env
```

#### Windows

```powershell
copy .env.example .env
```

Example configuration:

```env
SECRET_KEY=change_this_secret_key
JWT_SECRET=change_this_jwt_secret
DATABASE_URL=sqlite:///cybershield.db
ENCRYPTION_KEY=change_this_encryption_key

# Optional
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=eu-central-1
S3_BUCKET_NAME=

MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=
MAIL_PASSWORD=
```

---

### 5. Initialize the Database

```bash
python backend/init_db.py
```

If you are using the alternative initialization script:

```bash
python backend/database/init_db.py
```

---

### 6. Run the Backend Application

```bash
python backend/app.py
```

The backend will run at:

```text
http://127.0.0.1:5000
```

---

## Frontend Setup (React + Vite)

The repository also includes a **React-based security dashboard**.

### Install Frontend Dependencies

```bash
npm install
```

### Start Development Server

```bash
npm run dev
```

The frontend will be available at:

```text
http://localhost:5173
```

---

## Useful Development Commands

### Backend

```bash
# Run Flask app
python backend/app.py

# Initialize database
python backend/init_db.py
```

### Frontend

```bash
# Start development server
npm run dev

# Production build
npm run build

# Preview production build
npm run preview
```

---

## Security Features Included

### Authentication

* JWT authentication
* Role-based authorization
* 2FA support
* Password hashing with **bcrypt**

### Data Protection

* AES encryption
* Secure backup handling
* Environment-based secret management

### Monitoring

* Audit logs
* Security event tracking
* File scan logging
* Email alerting

### Infrastructure Security

* WAF integration
* Cloudflare template support
* Suspicious request filtering
* Key rotation scheduling

---

## CI/CD & Security Automation

The repository contains a **GitHub Actions security workflow**:

```text
.github/workflows/security.yml
```

This can be extended to include:

* Dependency vulnerability scanning
* Static Application Security Testing (**SAST**)
* Secret scanning
* Automated security checks
* Build validation

---

## Roadmap

### Planned Improvements

#### 🤖 AI & Machine Learning

* Advanced ML-based anomaly detection
* Automated threat classification
* Behavioral analysis engine

#### Cybersecurity Enhancements

* Automatic cyberattack detection
* Real-time intelligent notifications
* Malware sandbox integration
* Threat intelligence feeds

#### Platform Expansion

* Mobile application
* Multi-tenant architecture
* Azure / Jira / Microsoft Teams integration
* Enhanced management automation

#### Stability & Performance

* Continuous bug fixes
* Performance optimization
* Expanded test coverage
* Improved deployment tooling

---

## 🤝 Contributing

Contributions, ideas, and security-related suggestions are welcome.

### Steps

```bash
# Fork the repository
# Create a feature branch
git checkout -b feature/my-feature

# Commit changes
git commit -m "Add my feature"

# Push branch
git push origin feature/my-feature
```

Then open a **Pull Request**.

---

## Author

**Alexandru Cristian**

Cybersecurity Student • Security Researcher • Software Developer

* GitHub: **https://github.com/AlexandruCristian25**
* LinkedIn: **Alexandru Cristian Marincovici**

---

## Support the Project

If you find this project useful:

* **Star the repository**
* Report issues
* Suggest new features
* Contribute improvements

---

# CyberShield AI

### **Protect smarter. Respond faster. Stay secure.**

**CyberShield AI — Intelligent cybersecurity protection for modern infrastructure.**


<img width="1916" height="912" alt="image" src="https://github.com/user-attachments/assets/11298a27-725e-4736-adc3-10938e8814ae" />

<img width="1906" height="912" alt="image" src="https://github.com/user-attachments/assets/f2cb8b00-7cd1-4d12-8df1-fa828be89ebc" />

