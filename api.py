import os
import hashlib
import bcrypt
import hmac
import secrets
import logging
import time
import smtplib
import base64
from email.message import EmailMessage
from typing import Optional, Dict, List
from pathlib import Path
from argon2 import PasswordHasher, exceptions as argon_exceptions
from logging.handlers import RotatingFileHandler
from sqlalchemy import create_engine, Column, String, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# ===============================
# ⚙️ Config: Variabile de Mediu
# ===============================
PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "")
SQLITE_URL = os.getenv("SQLITE_URL", "sqlite:///security.db")
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
BLOCK_PERIOD = int(os.getenv("BLOCK_PERIOD", 300))
WINDOW_SECONDS = int(os.getenv("ATTEMPT_WINDOW", 60))
EMAIL_ALERTS_ENABLED = os.getenv("EMAIL_ALERTS_ENABLED", "true").lower() == "true"
EMAIL_ADMIN = os.getenv("ALERT_EMAIL", "admin@example.com")
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "security@yourdomain.com")
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() == "true"

# ===============================
# 📜 Secure Logger
# ===============================
logger = logging.getLogger("security_audit")
handler = RotatingFileHandler(".audit.log", maxBytes=5 * 1024 * 1024, backupCount=5)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ===============================
# 🔐 Hashers
# ===============================
argon2_hasher = PasswordHasher()

# ===============================
# 🗃️ Database Setup
# ===============================
engine = create_engine(SQLITE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)

class BlacklistedIP(Base):
    __tablename__ = "blacklisted_ips"
    ip = Column(String, primary_key=True)
    timestamp = Column(Float)

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(String, primary_key=True)
    ip_address = Column(String)
    timestamp = Column(Float)

Base.metadata.create_all(engine)

# ===============================
# 🚫 Brute-force & Blacklist Management
# ===============================
def save_blacklist_ip(ip_address: str):
    session = Session()
    session.merge(BlacklistedIP(ip=ip_address, timestamp=time.time()))
    session.commit()
    session.close()

def remove_expired_blacklist():
    session = Session()
    now = time.time()
    expired = session.query(BlacklistedIP).filter(BlacklistedIP.timestamp + BLOCK_PERIOD < now).all()
    for record in expired:
        session.delete(record)
    session.commit()
    session.close()

def is_ip_blocked(ip_address: str) -> bool:
    remove_expired_blacklist()
    session = Session()
    record = session.get(BlacklistedIP, ip_address)
    session.close()
    return bool(record)

def register_login_attempt(ip_address: str):
    session = Session()
    session.add(LoginAttempt(
        id=generate_secure_token(16),
        ip_address=ip_address,
        timestamp=time.time()
    ))
    session.commit()
    session.close()
    check_brute_force(ip_address)

def check_brute_force(ip_address: str):
    now = time.time()
    session = Session()
    attempts = session.query(LoginAttempt).filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp >= now - WINDOW_SECONDS
    ).count()
    session.close()
    if attempts >= MAX_LOGIN_ATTEMPTS:
        save_blacklist_ip(ip_address)
        send_bruteforce_alert(ip_address)
        logger.warning("IP %s blocat din cauza brute-force.", ip_address)

def send_bruteforce_alert(ip_address: str):
    if not EMAIL_ALERTS_ENABLED:
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = f"⚠️ Alertă brute-force: IP blocat {ip_address}"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_ADMIN
        msg.set_content(f"Sistemul a blocat IP-ul {ip_address} din cauza unui posibil atac brute-force.")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info("Alertă email trimisă pentru IP: %s", ip_address)
    except Exception as e:
        logger.error("Eroare trimitere alertă email: %s", e)

# ===============================
# 🔐 Parolă & Token Management
# ===============================
def hash_password(password: str, rounds: int = 12, use_argon2: bool = False) -> str:
    if not password or len(password) < 8 or len(password) > 512:
        raise ValueError("Parola trebuie să aibă între 8 și 512 caractere.")
    peppered = (password + PASSWORD_PEPPER).encode("utf-8")
    if use_argon2:
        return f"argon2${argon2_hasher.hash(peppered)}"
    if rounds < 4 or rounds > 18:
        raise ValueError("Runde bcrypt între 4 și 18.")
    hashed = bcrypt.hashpw(peppered, bcrypt.gensalt(rounds=rounds)).decode("utf-8")
    return f"bcrypt${hashed}"

def verify_password(password: str, hashed: str, ip_address: Optional[str] = None) -> bool:
    peppered = (password + PASSWORD_PEPPER).encode("utf-8")
    if ip_address and is_ip_blocked(ip_address):
        logger.error("IP %s blocat.", ip_address)
        return False

    success = False
    try:
        if hashed.startswith("bcrypt$"):
            success = bcrypt.checkpw(peppered, hashed[len("bcrypt$"):].encode("utf-8"))
        elif hashed.startswith("argon2$"):
            argon2_hasher.verify(hashed[len("argon2$"):], peppered)
            success = True
    except argon_exceptions.VerifyMismatchError:
        success = False
    except Exception as e:
        logger.error("Eroare verificare parolă: %s", e)
        success = False

    if ip_address:
        register_login_attempt(ip_address)

    return success

def generate_secure_token(length: int = 64) -> str:
    if length < 16:
        raise ValueError("Tokenul trebuie să aibă minim 16 caractere.")
    return secrets.token_hex(length // 2)

def hmac_sign_token(data: str, secret: str) -> str:
    return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()

def constant_time_compare(val1: str, val2: str) -> bool:
    return hmac.compare_digest(val1 or "", val2 or "")
