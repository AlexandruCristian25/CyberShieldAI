import os
import time
import secrets
import hashlib
import hmac
import logging
import smtplib
from email.message import EmailMessage
from typing import Optional, Dict
from contextlib import contextmanager
from sqlalchemy import create_engine, Column, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from argon2 import PasswordHasher, exceptions as argon_exceptions
from logging.handlers import RotatingFileHandler

# === Configurare ===
PEPPER = os.getenv("PASSWORD_PEPPER", "")
DB_URL = os.getenv("SQLITE_URL", "sqlite:///security.db")
SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "security@example.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "password")
EMAIL_ALERTS_ENABLED = os.getenv("EMAIL_ALERTS_ENABLED", "true").lower() == "true"
EMAIL_ADMIN = os.getenv("ALERT_EMAIL", "admin@example.com")
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "security@yourdomain.com")

# === Limite Brute Force ===
MAX_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
BLOCK_PERIOD = int(os.getenv("BLOCK_PERIOD", 300))  # secunde
WINDOW_SECONDS = int(os.getenv("ATTEMPT_WINDOW", 60))

# === Logger securizat ===
logger = logging.getLogger("security_audit")
handler = RotatingFileHandler(".audit.log", maxBytes=5 * 1024 * 1024, backupCount=3)
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# === ORM Setup ===
engine = create_engine(DB_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)

class BlacklistedIP(Base):
    __tablename__ = "blacklisted_ips"
    ip = Column(String, primary_key=True)
    timestamp = Column(Float)

Base.metadata.create_all(engine)

# === Context Manager pentru DB ===
@contextmanager
def get_session():
    session = Session()
    try:
        yield session
    finally:
        session.close()

# === Brute-force Protection ===
LOGIN_ATTEMPTS: Dict[str, list] = {}

def save_blacklist_ip(ip_address: str):
    with get_session() as session:
        session.merge(BlacklistedIP(ip=ip_address, timestamp=time.time()))
        session.commit()

def remove_expired_blacklist():
    now = time.time()
    with get_session() as session:
        expired = session.query(BlacklistedIP).filter(BlacklistedIP.timestamp + BLOCK_PERIOD < now).all()
        for record in expired:
            session.delete(record)
        session.commit()

def is_ip_blocked(ip_address: str) -> bool:
    remove_expired_blacklist()
    with get_session() as session:
        record = session.get(BlacklistedIP, ip_address)
        return bool(record)

def register_login_attempt(ip_address: str):
    now = time.time()
    LOGIN_ATTEMPTS.setdefault(ip_address, []).append(now)
    attempts = [t for t in LOGIN_ATTEMPTS[ip_address] if now - t < WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip_address] = attempts
    if len(attempts) >= MAX_ATTEMPTS:
        save_blacklist_ip(ip_address)
        send_bruteforce_alert(ip_address)
        logger.warning(f"IP {ip_address} blocat din cauza brute-force.")

def send_bruteforce_alert(ip_address: str):
    if not EMAIL_ALERTS_ENABLED:
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = f"⚠️ Alertă Brute Force: IP Blocare"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_ADMIN
        msg.set_content(f"Sistemul a blocat IP-ul {ip_address} din cauza multiple încercări de login.")

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"[EMAIL ALERT] Trimis către {EMAIL_ADMIN} pentru IP: {ip_address}")
    except Exception as e:
        logger.error(f"[EMAIL ERROR] {str(e)}")

# === Password Security ===
argon2_hasher = PasswordHasher()

def hash_password(password: str, rounds: int = 12, use_argon2: bool = False) -> str:
    if not password or len(password) < 8:
        raise ValueError("Parola minim 8 caractere.")
    peppered = (password + PEPPER).encode("utf-8")
    if use_argon2:
        return f"argon2${argon2_hasher.hash(peppered)}"
    if not 4 <= rounds <= 18:
        raise ValueError("Runde bcrypt între 4 și 18.")
    hashed = bcrypt.hashpw(peppered, bcrypt.gensalt(rounds=rounds)).decode()
    return f"bcrypt${hashed}"

def verify_password(password: str, hashed: str, ip_address: Optional[str] = None) -> bool:
    peppered = (password + PEPPER).encode("utf-8")
    if ip_address and is_ip_blocked(ip_address):
        logger.error(f"IP {ip_address} este blocat.")
        return False
    try:
        if hashed.startswith("bcrypt$"):
            result = bcrypt.checkpw(peppered, hashed[len("bcrypt$"):].encode())
        elif hashed.startswith("argon2$"):
            argon2_hasher.verify(hashed[len("argon2$"):], peppered)
            result = True
        else:
            logger.warning("Hash necunoscut.")
            result = False
    except argon_exceptions.VerifyMismatchError:
        logger.warning("Verificare eșuată: mismatch")
        result = False
    except Exception as e:
        logger.error(f"Eroare verificare: {e}")
        result = False

    if ip_address:
        register_login_attempt(ip_address)
    return result

def sha256_hash(text: str) -> str:
    if not text:
        raise ValueError("Text gol pentru hash.")
    return hashlib.sha256(text.encode()).hexdigest()

def generate_secure_token(length: int = 64) -> str:
    if length < 16:
        raise ValueError("Tokenul minim 16 caractere.")
    return secrets.token_hex(length // 2)

def constant_time_compare(val1: str, val2: str) -> bool:
    if not val1 or not val2:
        logger.warning("Comparare între valori nule.")
        return False
    return hmac.compare_digest(val1, val2)
