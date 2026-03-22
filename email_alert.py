import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from typing import List
from config import SMTP_CONFIG

logger = logging.getLogger("email_alerts")
logger.setLevel(logging.INFO)

def send_email(subject: str, body: str, to_emails: List[str]):
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = f"CyberShield AI <{SMTP_CONFIG['username']}>"
    msg["To"] = ", ".join(to_emails)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_CONFIG["server"], SMTP_CONFIG["port"], timeout=SMTP_CONFIG.get("timeout", 15)) as server:
            if SMTP_CONFIG.get("use_tls", True):
                server.starttls(context=context)
            server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
            server.send_message(msg)
        logger.info(f"[EMAIL SENT] Către: {to_emails}")
        return True
    except Exception as e:
        logger.error(f"[EMAIL ERROR] Trimitere eșuată: {e}")
        return False

def send_suspicious_login_alert(to_email: str, ip_address: str):
    """
    Trimite email de alertă pentru autentificare suspectă.
    """
    subject = "⚠️ Alertă de securitate - Autentificare suspectă detectată"
    body = (
        f"Salut,\n\n"
        f"A fost detectată o autentificare suspectă în contul tău.\n\n"
        f"Adresă IP: {ip_address}\n"
        f"Dacă nu ai fost tu, îți recomandăm să îți schimbi parola imediat și să activezi autentificarea 2FA.\n\n"
        f"--\nEchipa CyberShield AI"
    )
    return send_email(subject, body, [to_email])
