import uuid
import smtplib
import pyotp
import asyncio
import jwt
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from config import SMTP_USERNAME, SMTP_PASSWORD, SMTP_PORT, SMTP_SERVER, FRONTEND_RESET_LINK, JWT_SECRET
from db import get_db_connection
from encryptor import hash_password, verify_password
from logger import log_event

def generate_reset_token(user_id: int) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_reset_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        log_event("reset_token_expired")
        return None
    except jwt.InvalidTokenError:
        log_event("reset_token_invalid")
        return None

async def send_email_async(to: str, subject: str, html_body: str):
    msg = MIMEText(html_body, "html")
    msg['Subject'] = subject
    msg['From'] = SMTP_USERNAME
    msg['To'] = to

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        log_event("email_sent", metadata={"recipient": to, "subject": subject})
    except Exception as e:
        log_event("email_failed", metadata={"error": str(e), "recipient": to})

def request_password_reset(email: str, ip_address: str = None, user_agent: str = None) -> bool:
    if not email or "@" not in email:
        return False

    try:
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if not user:
            log_event("password_reset_request_invalid_email", metadata={"email": email, "ip": ip_address})
            return False

        token = generate_reset_token(user["id"])
        reset_url = f"{FRONTEND_RESET_LINK}/{token}"
        email_body = f"""
        <html>
          <body>
            <p>Salut,</p>
            <p>Am primit o solicitare pentru resetarea parolei tale. Dacă nu ai inițiat această cerere, ignoră acest email.</p>
            <p><a href="{reset_url}" style="background:blue;color:white;padding:10px;border-radius:5px;text-decoration:none;">Resetează parola</a></p>
            <p>Link-ul va expira în 1 oră.</p>
          </body>
        </html>
        """

        asyncio.create_task(send_email_async(email, "Resetare parolă - CyberShield AI", email_body))
        log_event("password_reset_requested", user_id=user["id"], metadata={"ip": ip_address, "agent": user_agent})
        return True

    except Exception as e:
        log_event("password_reset_exception", metadata={"error": str(e)})
        return False

def verify_2fa_code(secret: str, code: str, ip_address: str = None, user_agent: str = None) -> bool:
    try:
        totp = pyotp.TOTP(secret)
        valid = totp.verify(code, valid_window=1)
        log_event("2fa_verify_attempt", metadata={"result": valid, "ip": ip_address, "agent": user_agent})
        return valid
    except Exception as e:
        log_event("2fa_verify_failed", metadata={"error": str(e)})
        return False

def generate_2fa_secret() -> str:
    return pyotp.random_base32()
