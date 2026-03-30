# 🛡️ CyberShield AI

------------------------------------------------------------------------

# 🇬🇧 English Version

## Intelligent Cybersecurity Protection for Modern Infrastructure

CyberShield AI is a modular cybersecurity platform designed to help
organizations monitor, protect, and manage their digital infrastructure
against modern cyber threats.

Built with a strong focus on **security, transparency, and automation**,
CyberShield AI combines **AI-powered assistance**, **encrypted
backups**, **audit logging**, and **firewall/WAF integrations** into a
unified platform.

> Help security teams detect threats faster, respond smarter, and
> maintain full visibility over their systems.

------------------------------------------------------------------------

## 🚀 Overview

Modern organizations face increasingly sophisticated cyber threats
including ransomware, credential attacks, and infrastructure
exploitation.

CyberShield AI provides a centralized platform that enables:

-   Real-time security monitoring
-   Secure authentication and access control
-   Encrypted backup management
-   Audit logging for compliance
-   AI-assisted security insights
-   Web Application Firewall (WAF) integration

The platform is designed to be **lightweight, extensible, and easy to
integrate into existing infrastructure**.

------------------------------------------------------------------------

## 🧠 Key Features

### 🔐 Secure Authentication

CyberShield AI includes a **JWT-based authentication system** with
role-based access control.

Features:

-   Secure login and session handling
-   Role-based permissions (Admin, Analyst, Auditor)
-   Token expiration and refresh mechanisms
-   Protection against brute-force login attempts

------------------------------------------------------------------------

### 📜 Advanced Audit Logging

CyberShield AI includes a **comprehensive audit logging system**
designed for transparency and accountability.

The system tracks:

-   User actions
-   Security events
-   System operations
-   Administrative changes

Logs can be exported and used for **security analysis or compliance
reporting**.

------------------------------------------------------------------------

### 🔐 Encrypted Backup and Recovery

CyberShield AI provides **secure backup capabilities using AES
encryption**.

Features:

-   Encrypted database backups
-   Secure key management
-   Fast recovery in case of incidents
-   Protection against ransomware-related data loss

------------------------------------------------------------------------

### 🧠 AI Security Assistant

The integrated AI assistant helps security teams interpret system data
and identify potential risks.

Capabilities:

-   security insights
-   contextual explanations
-   incident response suggestions
-   threat awareness recommendations

------------------------------------------------------------------------

### 🧱 WAF Integration

CyberShield AI supports **Cloudflare Web Application Firewall
templates**.

Protection against:

-   SQL Injection
-   Cross-Site Scripting (XSS)
-   automated bot attacks
-   suspicious traffic patterns

------------------------------------------------------------------------

## ⚙️ Technology Stack

Backend - Python - Flask

Database - SQLAlchemy ORM

Security - AES encryption - JWT authentication - secure token handling

Infrastructure - environment configuration via `.env` - modular
architecture

------------------------------------------------------------------------

## ⚙️ Installation & Setup

### 1. Clone the Repository

``` bash
git clone https://github.com/AlexandruCristian25/CyberShieldAI.git
cd CyberShieldAI
```

### 2. Create Virtual Environment

Linux / macOS

``` bash
python3 -m venv venv
source venv/bin/activate
```

Windows

``` bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

``` bash
pip install -r requirements.txt
```

If the file does not exist:

``` bash
pip install flask sqlalchemy python-dotenv pyjwt cryptography
```

### 4. Configure Environment Variables

Create the configuration file:

``` bash
cp .env.example .env
```

Example configuration:

    SECRET_KEY=your_secret_key
    JWT_SECRET=your_jwt_secret
    DATABASE_URL=sqlite:///cybershield.db
    ENCRYPTION_KEY=your_encryption_key

### 5. Run the Application

``` bash
python app.py
```

Open in browser:

    http://127.0.0.1:5000

------------------------------------------------------------------------

# 🇷🇴 Versiunea în Limba Română

## Platformă Inteligentă de Securitate Cibernetică

CyberShield AI este o platformă modulară de securitate cibernetică
concepută pentru a ajuta organizațiile să monitorizeze, protejeze și
gestioneze infrastructura lor digitală împotriva amenințărilor
cibernetice moderne.

Platforma combină:

-   asistență bazată pe inteligență artificială
-   backup criptat
-   audit al activităților
-   integrare firewall și WAF

Totul într-un singur sistem unificat.

> Scopul CyberShield AI este să ajute echipele de securitate să
> detecteze amenințările mai rapid și să răspundă mai eficient.

------------------------------------------------------------------------

## 🚀 Prezentare Generală

Organizațiile moderne se confruntă cu amenințări tot mai complexe:

-   ransomware
-   atacuri asupra autentificării
-   exploatarea infrastructurii

CyberShield AI oferă:

-   monitorizare în timp real
-   control securizat al accesului
-   backup criptat al datelor
-   jurnalizare de audit
-   analiză asistată de AI
-   integrare Web Application Firewall

------------------------------------------------------------------------

## 🧠 Funcționalități Principale

### 🔐 Autentificare securizată

Sistem de autentificare bazat pe **JWT** cu control al accesului pe
roluri.

Caracteristici:

-   login securizat
-   roluri utilizator (Admin, Analist, Auditor)
-   expirare și regenerare token
-   protecție împotriva atacurilor brute-force

------------------------------------------------------------------------

### 📜 Audit și jurnalizare

CyberShield AI include un sistem complet de **audit al activităților**.

Sunt monitorizate:

-   acțiunile utilizatorilor
-   evenimente de securitate
-   modificări administrative

Logurile pot fi exportate pentru analiză sau conformitate.

------------------------------------------------------------------------

### 🔐 Backup criptat

Platforma oferă backup securizat folosind **criptare AES**.

Funcționalități:

-   backup criptat al bazei de date
-   management securizat al cheilor
-   restaurare rapidă
-   protecție împotriva ransomware

------------------------------------------------------------------------

### 🧠 Asistent AI

Asistentul AI integrat ajută echipele de securitate să analizeze datele
sistemului.

Poate oferi:

-   insight-uri de securitate
-   explicații contextuale
-   recomandări pentru răspuns la incidente

------------------------------------------------------------------------

### 🧱 Integrare WAF

CyberShield AI permite integrarea cu **Cloudflare Web Application
Firewall**.

Protecție împotriva:

-   SQL Injection
-   XSS
-   atacuri automate
-   trafic suspect

------------------------------------------------------------------------

## ⚙️ Instalare

### 1. Clonarea proiectului

``` bash
git clone https://github.com/AlexandruCristian25/CyberShieldAI.git
cd CyberShieldAI
```

### 2. Crearea mediului virtual

Linux / macOS

``` bash
python3 -m venv venv
source venv/bin/activate
```

Windows

``` bash
python -m venv venv
venv\Scripts\activate
```

### 3. Instalarea dependențelor

``` bash
pip install -r requirements.txt
```

### 4. Configurarea fișierului .env

``` bash
cp .env.example .env
```

### 5. Rularea aplicației

``` bash
python app.py
```

Aplicația va rula la:

    http://127.0.0.1:5000

------------------------------------------------------------------------

## 👨‍💻 Autor

Alexandru Cristian\
Cybersecurity Student & Security Researcher

GitHub: https://github.com/AlexandruCristian25

------------------------------------------------------------------------

## 🛡️ CyberShield AI

Protect smarter. Respond faster. Stay secure.
