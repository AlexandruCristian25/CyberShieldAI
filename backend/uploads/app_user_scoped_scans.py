from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS

import sqlite3
import os
import hashlib
import requests
import csv
import io
import smtplib
from io import BytesIO
from email.message import EmailMessage

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

DATABASE = "cybershield_database.db"
UPLOAD_FOLDER = "uploads"

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# =========================
# GMAIL ALERT CONFIGURATION
# =========================

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

EMAIL_SENDER = "cybershieldenterprise30@gmail.com"
EMAIL_PASSWORD = "xipa dajh thvp oovj"

ADMIN_EMAIL = "alexandrucristian995@yahoo.com"

MAX_FAILED_LOGIN_ATTEMPTS = 5
BRUTE_FORCE_WINDOW_MINUTES = 15

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_admin_schema():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(users)")
    columns = [col["name"] for col in cursor.fetchall()]

    if "is_blocked" not in columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0"
        )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS failed_login_attempts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            source_ip TEXT,
            failed_count INTEGER DEFAULT 0,
            last_failed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(email, source_ip)
        )
        """
    )

    conn.commit()
    conn.close()


ensure_admin_schema()


def require_admin():
    admin_id = (
        request.headers.get("X-Admin-User-Id")
        or request.args.get("admin_id")
    )

    if not admin_id:
        return None

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, role, is_blocked
        FROM users
        WHERE id=?
        """,
        (admin_id,)
    )

    admin = cursor.fetchone()
    conn.close()

    if not admin:
        return None

    if admin["role"] != "admin":
        return None

    if admin["is_blocked"]:
        return None

    return admin



def get_ip_geolocation(ip_address):
    if not ip_address:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "latitude": None,
            "longitude": None,
            "location": "Unknown"
        }

    if ip_address in ["127.0.0.1", "::1", "localhost"]:
        return {
            "country": "Localhost",
            "city": "Local Machine",
            "isp": "Local Network",
            "latitude": None,
            "longitude": None,
            "location": "Localhost / Local Machine"
        }

    try:
        url = (
            f"http://ip-api.com/json/{ip_address}"
            "?fields=status,country,city,isp,lat,lon,query"
        )

        response = requests.get(
            url,
            timeout=5
        )

        data = response.json()

        if data.get("status") != "success":
            return {
                "country": "Unknown",
                "city": "Unknown",
                "isp": "Unknown",
                "latitude": None,
                "longitude": None,
                "location": "IP location unavailable"
            }

        country = data.get("country") or "Unknown"
        city = data.get("city") or "Unknown"
        isp = data.get("isp") or "Unknown"
        latitude = data.get("lat")
        longitude = data.get("lon")

        return {
            "country": country,
            "city": city,
            "isp": isp,
            "latitude": latitude,
            "longitude": longitude,
            "location": f"{city}, {country} | ISP: {isp}"
        }

    except Exception as e:
        print("IP geolocation error:", e)

        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "latitude": None,
            "longitude": None,
            "location": "IP location lookup failed"
        }



def get_admin_emails():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT email
        FROM users
        WHERE role='admin'
        AND is_blocked=0
        """
    )

    rows = cursor.fetchall()
    conn.close()

    return [row["email"] for row in rows if row["email"]]


def get_user_security_context(user_id):
    if not user_id:
        return {
            "username": "Unknown",
            "email": "Unknown",
            "role": "guest",
            "password_hash_preview": "Unknown"
        }

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            username,
            email,
            role,
            password
        FROM users
        WHERE id=?
        """,
        (user_id,)
    )

    user = cursor.fetchone()
    conn.close()

    if not user:
        return {
            "username": "Unknown",
            "email": "Unknown",
            "role": "guest",
            "password_hash_preview": "Unknown"
        }

    return {
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "password_hash_preview": user["password"][:24] + "..."
    }


def create_security_alert_pdf(alert_data):
    buffer = BytesIO()

    pdf = canvas.Canvas(
        buffer,
        pagesize=A4
    )

    width, height = A4

    pdf.setTitle("CyberShield AI Security Alert")

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(
        50,
        height - 60,
        "CyberShield AI - Security Alert"
    )

    pdf.setFont("Helvetica", 10)
    pdf.drawString(
        50,
        height - 85,
        "Automatic alert generated for suspicious or malicious activity."
    )

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(
        50,
        height - 125,
        "Incident Details"
    )

    y = height - 155
    pdf.setFont("Helvetica", 9)

    lines = [
        f"Threat Type: {alert_data.get('threat_type')}",
        f"Status: {alert_data.get('status')}",
        f"Reason: {alert_data.get('reason')}",
        f"User ID: {alert_data.get('user_id')}",
        f"Username: {alert_data.get('username')}",
        f"Email: {alert_data.get('email')}",
        f"Role: {alert_data.get('role')}",
        f"Password Hash Preview: {alert_data.get('password_hash_preview')}",
        f"Source IP: {alert_data.get('source_ip')}",
        f"Country: {alert_data.get('country')}",
        f"City: {alert_data.get('city')}",
        f"ISP: {alert_data.get('isp')}",
        f"Coordinates: {alert_data.get('latitude')}, {alert_data.get('longitude')}",
        f"Location: {alert_data.get('location')}",
        f"User Agent / Digital Fingerprint: {alert_data.get('user_agent')}",
        f"Filename: {alert_data.get('filename')}",
        f"File Size: {alert_data.get('filesize')} bytes",
        f"SHA-256 File Fingerprint: {alert_data.get('file_hash')}",
        f"Scan Engine: {alert_data.get('scan_engine')}",
        f"Scan ID: {alert_data.get('scan_id')}",
    ]

    for line in lines:
        pdf.drawString(
            50,
            y,
            str(line)[:115]
        )
        y -= 18

        if y < 80:
            pdf.showPage()
            y = height - 60
            pdf.setFont("Helvetica", 9)

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(
        50,
        y - 15,
        "Recommended Admin Action"
    )

    pdf.setFont("Helvetica", 9)
    pdf.drawString(
        50,
        y - 40,
        "Review the user activity, verify uploaded files, and block the account if necessary."
    )

    pdf.setFont("Helvetica", 8)
    pdf.drawString(
        50,
        40,
        "Generated by CyberShield AI Enterprise Security Platform"
    )

    pdf.save()
    buffer.seek(0)

    return buffer.getvalue()


def send_security_alert(
    subject,
    body,
    pdf_bytes=None,
    pdf_filename=None
):
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        print(
            "Email alert not sent: Gmail configuration missing"
        )
        return False

    try:

        msg = EmailMessage()

        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = ADMIN_EMAIL

        msg.set_content(body)

        if pdf_bytes and pdf_filename:

            msg.add_attachment(
                pdf_bytes,
                maintype="application",
                subtype="pdf",
                filename=pdf_filename
            )

        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT
        ) as server:

            server.starttls()

            server.login(
                EMAIL_SENDER,
                EMAIL_PASSWORD
            )

            server.send_message(msg)

        print(
            "CyberShield AI alert email sent successfully"
        )

        return True

    except Exception as e:

        print(
            "CyberShield AI email error:",
            e
        )

        return False

def trigger_security_email_alert(
    user_id,
    scan_id,
    filename,
    filesize,
    file_hash,
    status,
    reason
):
    user_context = get_user_security_context(user_id)
    geo = get_ip_geolocation(request.remote_addr)

    alert_data = {
        "threat_type": "Suspicious/Malicious File Upload",
        "status": status,
        "reason": reason,
        "user_id": user_id or "Unknown",
        "username": user_context["username"],
        "email": user_context["email"],
        "role": user_context["role"],
        "password_hash_preview": user_context["password_hash_preview"],
        "source_ip": request.remote_addr,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "latitude": geo["latitude"],
        "longitude": geo["longitude"],
        "location": geo["location"],
        "user_agent": request.headers.get("User-Agent"),
        "filename": filename,
        "filesize": filesize,
        "file_hash": file_hash,
        "scan_engine": "CyberShield + VirusTotal",
        "scan_id": scan_id
    }

    body = f"""
CyberShield AI Security Alert

Threat Type: {alert_data["threat_type"]}
Status: {alert_data["status"]}
Reason: {alert_data["reason"]}

User ID: {alert_data["user_id"]}
Username: {alert_data["username"]}
Email: {alert_data["email"]}
Role: {alert_data["role"]}
Password Hash Preview: {alert_data["password_hash_preview"]}

Source IP: {alert_data["source_ip"]}
Country: {alert_data["country"]}
City: {alert_data["city"]}
ISP: {alert_data["isp"]}
Coordinates: {alert_data["latitude"]}, {alert_data["longitude"]}
Location: {alert_data["location"]}
Digital Fingerprint / User Agent:
{alert_data["user_agent"]}

Uploaded File:
Filename: {alert_data["filename"]}
File Size: {alert_data["filesize"]} bytes
SHA-256 Fingerprint: {alert_data["file_hash"]}
Scan Engine: {alert_data["scan_engine"]}
Scan ID: {alert_data["scan_id"]}

Recommended Action:
Review this user in the Admin Panel, verify the uploaded file, and block/delete the account if necessary.
"""

    pdf_bytes = create_security_alert_pdf(alert_data)

    send_security_alert(
        subject="CyberShield AI Alert - Suspicious Activity Detected",
        body=body,
        pdf_bytes=pdf_bytes,
        pdf_filename=f"cybershield_security_alert_scan_{scan_id}.pdf"
    )




def reset_failed_login_attempts(email):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM failed_login_attempts
        WHERE email=?
        """,
        (email,)
    )

    conn.commit()
    conn.close()


def register_failed_login_attempt(email):
    source_ip = request.remote_addr or "unknown"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            failed_count,
            last_failed_at
        FROM failed_login_attempts
        WHERE email=?
        AND source_ip=?
        """,
        (
            email,
            source_ip
        )
    )

    attempt = cursor.fetchone()

    if attempt:
        cursor.execute(
            """
            UPDATE failed_login_attempts
            SET
                failed_count = failed_count + 1,
                last_failed_at = CURRENT_TIMESTAMP
            WHERE email=?
            AND source_ip=?
            """,
            (
                email,
                source_ip
            )
        )

        failed_count = attempt["failed_count"] + 1

    else:
        cursor.execute(
            """
            INSERT INTO failed_login_attempts(
                email,
                source_ip,
                failed_count
            )
            VALUES (?, ?, ?)
            """,
            (
                email,
                source_ip,
                1
            )
        )

        failed_count = 1

    conn.commit()
    conn.close()

    return failed_count


def block_user_for_bruteforce(user):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET is_blocked=1
        WHERE id=?
        """,
        (user["id"],)
    )

    conn.commit()
    conn.close()


def trigger_bruteforce_email_alert(user, failed_count):
    user_context = get_user_security_context(user["id"])
    geo = get_ip_geolocation(request.remote_addr)

    alert_data = {
        "threat_type": "Potential Brute Force Attack",
        "status": "Critical",
        "reason": (
            f"{failed_count} failed login attempts detected "
            f"for the same account."
        ),
        "user_id": user["id"],
        "username": user_context["username"],
        "email": user_context["email"],
        "role": user_context["role"],
        "password_hash_preview": user_context["password_hash_preview"],
        "source_ip": request.remote_addr,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "latitude": geo["latitude"],
        "longitude": geo["longitude"],
        "location": geo["location"],
        "user_agent": request.headers.get("User-Agent"),
        "filename": "N/A",
        "filesize": "N/A",
        "file_hash": "N/A",
        "scan_engine": "CyberShield Brute Force Protection",
        "scan_id": "N/A"
    }

    body = f"""
CyberShield AI Brute Force Alert

Threat Type: {alert_data["threat_type"]}
Status: {alert_data["status"]}
Reason: {alert_data["reason"]}

User ID: {alert_data["user_id"]}
Username: {alert_data["username"]}
Email: {alert_data["email"]}
Role: {alert_data["role"]}
Password Hash Preview: {alert_data["password_hash_preview"]}

Source IP: {alert_data["source_ip"]}
Country: {alert_data["country"]}
City: {alert_data["city"]}
ISP: {alert_data["isp"]}
Coordinates: {alert_data["latitude"]}, {alert_data["longitude"]}
Location: {alert_data["location"]}
Digital Fingerprint / User Agent:
{alert_data["user_agent"]}

Security Action:
The account was automatically blocked after too many failed login attempts.

Recommended Admin Action:
Open the Admin Panel, review the audit journal, verify the user, and unblock only if the activity is legitimate.
"""

    pdf_bytes = create_security_alert_pdf(alert_data)

    send_security_alert(
        subject="CyberShield AI Alert - Potential Brute Force Attack",
        body=body,
        pdf_bytes=pdf_bytes,
        pdf_filename=f"cybershield_bruteforce_alert_user_{user['id']}.pdf"
    )



def log_audit(
    user_id,
    action_type,
    action,
    role="user",
    target_resource=None,
    severity_level="info"
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO audit_log(
                user_id,
                action_type,
                role,
                action,
                target_resource,
                source_ip,
                user_agent,
                severity_level
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                action_type,
                role,
                action,
                target_resource,
                request.remote_addr,
                request.headers.get("User-Agent"),
                severity_level
            )
        )

        conn.commit()
        conn.close()

    except Exception as e:
        print("Audit log error:", e)


def check_virustotal(file_hash):
    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "status": "Unknown",
            "reason": "VirusTotal API key not configured",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            return {
                "available": True,
                "status": "Unknown",
                "reason": "File hash not found in VirusTotal database",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }

        if response.status_code != 200:
            return {
                "available": False,
                "status": "Unknown",
                "reason": f"VirusTotal error: {response.status_code}",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }

        data = response.json()

        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            status = "Malicious"
            reason = f"VirusTotal detected malware: {malicious} engines"
        elif suspicious > 0:
            status = "Suspicious"
            reason = f"VirusTotal marked file suspicious: {suspicious} engines"
        else:
            status = "Clean"
            reason = "VirusTotal found no malicious detections"

        return {
            "available": True,
            "status": status,
            "reason": reason,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected
        }

    except Exception as e:
        return {
            "available": False,
            "status": "Unknown",
            "reason": f"VirusTotal request failed: {str(e)}",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }


@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({
            "success": False,
            "message": "Missing fields"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO users(
                username,
                email,
                password,
                role,
                is_blocked
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                email,
                generate_password_hash(password),
                "user",
                0
            )
        )

        conn.commit()
        user_id = cursor.lastrowid

        log_audit(
            user_id=user_id,
            action_type="REGISTER",
            action=f"New account created for {email}",
            role="user",
            target_resource=email,
            severity_level="info"
        )

        return jsonify({
            "success": True,
            "message": "Account created successfully"
        })

    except sqlite3.IntegrityError:
        return jsonify({
            "success": False,
            "message": "Username or email already exists"
        }), 400

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password are required"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            email,
            password,
            role,
            is_blocked
        FROM users
        WHERE email=?
        """,
        (email,)
    )

    user = cursor.fetchone()
    conn.close()

    if not user:
        log_audit(
            user_id=None,
            action_type="LOGIN_FAILED",
            action=f"Login failed. User not found: {email}",
            role="guest",
            target_resource=email,
            severity_level="warning"
        )

        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    if user["is_blocked"]:
        log_audit(
            user_id=user["id"],
            action_type="LOGIN_BLOCKED",
            action=f"Blocked user attempted login: {email}",
            role=user["role"],
            target_resource=email,
            severity_level="warning"
        )

        return jsonify({
            "success": False,
            "message": "Account is blocked. Contact administrator."
        }), 403

    if not check_password_hash(user["password"], password):
        failed_count = register_failed_login_attempt(email)

        log_audit(
            user_id=user["id"],
            action_type="LOGIN_FAILED",
            action=(
                f"Wrong password for {email}. "
                f"Failed attempts: {failed_count}/{MAX_FAILED_LOGIN_ATTEMPTS}"
            ),
            role=user["role"],
            target_resource=email,
            severity_level="warning"
        )

        if failed_count >= MAX_FAILED_LOGIN_ATTEMPTS:
            block_user_for_bruteforce(user)

            log_audit(
                user_id=user["id"],
                action_type="BRUTE_FORCE_BLOCK",
                action=(
                    f"Account automatically blocked after "
                    f"{failed_count} failed login attempts: {email}"
                ),
                role=user["role"],
                target_resource=email,
                severity_level="critical"
            )

            trigger_bruteforce_email_alert(
                user=user,
                failed_count=failed_count
            )

            return jsonify({
                "success": False,
                "message": (
                    "Account blocked due to multiple failed login attempts. "
                    "Contact administrator."
                )
            }), 403

        remaining_attempts = max(
            0,
            MAX_FAILED_LOGIN_ATTEMPTS - failed_count
        )

        return jsonify({
            "success": False,
            "message": (
                f"Wrong password. "
                f"Remaining attempts before block: {remaining_attempts}"
            )
        }), 401

    reset_failed_login_attempts(email)

    log_audit(
        user_id=user["id"],
        action_type="LOGIN_SUCCESS",
        action=f"User logged in: {email}",
        role=user["role"],
        target_resource=email,
        severity_level="info"
    )

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "is_blocked": user["is_blocked"]
        }
    })


@app.route("/stats", methods=["GET"])
def stats():
    user_id = request.args.get("user_id")

    conn = get_db_connection()
    cursor = conn.cursor()

    if user_id:
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM file_scans
            WHERE user_id=?
            """,
            (user_id,)
        )
    else:
        cursor.execute(
            "SELECT COUNT(*) AS total FROM file_scans"
        )

    files_scanned = cursor.fetchone()["total"]

    if user_id:
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM file_scans
            WHERE is_malicious=1
            AND user_id=?
            """,
            (user_id,)
        )
    else:
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM file_scans
            WHERE is_malicious=1
            """
        )

    threats_blocked = cursor.fetchone()["total"]

    security_score = max(
        0,
        100 - (threats_blocked * 2)
    )

    conn.close()

    return jsonify({
        "threats_blocked": threats_blocked,
        "files_scanned": files_scanned,
        "security_score": security_score
    })


@app.route("/scan", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({
            "success": False,
            "message": "No file selected"
        }), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({
            "success": False,
            "message": "No file selected"
        }), 400

    user_id = request.form.get("user_id")
    filename = secure_filename(file.filename)

    filepath = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    file.save(filepath)
    filesize = os.path.getsize(filepath)

    sha256_hash = hashlib.sha256()

    with open(filepath, "rb") as f:
        for block in iter(
            lambda: f.read(4096),
            b""
        ):
            sha256_hash.update(block)

    file_hash = sha256_hash.hexdigest()
    vt_result = check_virustotal(file_hash)

    status = vt_result["status"]
    reason = vt_result["reason"]

    dangerous_extensions = [
        ".exe",
        ".bat",
        ".cmd",
        ".vbs",
        ".ps1",
        ".scr",
        ".js",
        ".jar",
        ".msi"
    ]

    for ext in dangerous_extensions:
        if filename.lower().endswith(ext):
            if status == "Clean" or status == "Unknown":
                status = "Suspicious"
                reason = f"Suspicious file extension detected locally: {ext}"
            break

    is_malicious = 1 if status in [
        "Suspicious",
        "Malicious"
    ] else 0

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO file_scans(
            filename,
            file_hash,
            filesize,
            user_id,
            scan_engine,
            is_malicious,
            reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            file_hash,
            filesize,
            user_id,
            "CyberShield + VirusTotal",
            is_malicious,
            reason
        )
    )

    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()

    log_audit(
        user_id=user_id,
        action_type="FILE_SCAN",
        action=f"Scanned file: {filename}",
        role="user",
        target_resource=filename,
        severity_level=(
            "warning"
            if is_malicious
            else "info"
        )
    )

    if is_malicious:
        trigger_security_email_alert(
            user_id=user_id,
            scan_id=scan_id,
            filename=filename,
            filesize=filesize,
            file_hash=file_hash,
            status=status,
            reason=reason
        )

    return jsonify({
        "success": True,
        "message": f"File '{filename}' scanned successfully",
        "scan_id": scan_id,
        "filename": filename,
        "sha256": file_hash,
        "filesize": filesize,
        "status": status,
        "reason": reason,
        "report_url": f"/report/{scan_id}",
        "virustotal": {
            "available": vt_result["available"],
            "malicious": vt_result["malicious"],
            "suspicious": vt_result["suspicious"],
            "harmless": vt_result["harmless"],
            "undetected": vt_result["undetected"]
        }
    })


@app.route("/scans", methods=["GET"])
def get_scans():
    user_id = request.args.get("user_id")

    conn = get_db_connection()
    cursor = conn.cursor()

    if user_id:
        cursor.execute(
            """
            SELECT
                id,
                filename,
                file_hash,
                filesize,
                is_malicious,
                reason,
                scan_engine,
                timestamp
            FROM file_scans
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT 50
            """,
            (user_id,)
        )
    else:
        cursor.execute(
            """
            SELECT
                id,
                filename,
                file_hash,
                filesize,
                is_malicious,
                reason,
                scan_engine,
                timestamp
            FROM file_scans
            ORDER BY id DESC
            LIMIT 50
            """
        )

    rows = cursor.fetchall()
    conn.close()

    scans = []

    for row in rows:
        scans.append({
            "id": row["id"],
            "filename": row["filename"],
            "sha256": row["file_hash"],
            "size": row["filesize"],
            "status": (
                "Suspicious"
                if row["is_malicious"]
                else "Clean"
            ),
            "reason": row["reason"],
            "scan_engine": row["scan_engine"],
            "scan_date": row["timestamp"],
            "report_url": f"/report/{row['id']}"
        })

    return jsonify(scans)


@app.route("/history", methods=["GET"])
def history():
    return get_scans()


@app.route("/audit", methods=["GET"])
def audit():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            timestamp,
            user_id,
            action_type,
            role,
            action,
            target_resource,
            source_ip,
            severity_level
        FROM audit_log
        ORDER BY id DESC
        LIMIT 50
        """
    )

    rows = cursor.fetchall()
    conn.close()

    logs = []

    for row in rows:
        logs.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "user_id": row["user_id"],
            "action_type": row["action_type"],
            "role": row["role"],
            "action": row["action"],
            "target_resource": row["target_resource"],
            "source_ip": row["source_ip"],
            "severity_level": row["severity_level"]
        })

    return jsonify(logs)


@app.route("/export/scans", methods=["GET"])
def export_scans():
    user_id = request.args.get("user_id")

    conn = get_db_connection()
    cursor = conn.cursor()

    if user_id:
        cursor.execute(
            """
            SELECT
                filename,
                file_hash,
                filesize,
                is_malicious,
                reason,
                scan_engine,
                timestamp
            FROM file_scans
            WHERE user_id=?
            ORDER BY id DESC
            """,
            (user_id,)
        )
    else:
        cursor.execute(
            """
            SELECT
                filename,
                file_hash,
                filesize,
                is_malicious,
                reason,
                scan_engine,
                timestamp
            FROM file_scans
            ORDER BY id DESC
            """
        )

    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Filename",
        "Location",
        "SHA256",
        "File Size",
        "Status",
        "Reason",
        "Scan Engine",
        "Scan Date"
    ])

    for row in rows:
        status = (
            "Suspicious"
            if row["is_malicious"]
            else "Clean"
        )

        writer.writerow([
            row["filename"],
            f"uploads/{row['filename']}",
            row["file_hash"],
            row["filesize"],
            status,
            row["reason"],
            row["scan_engine"],
            row["timestamp"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=cybershield_scan_history.csv"
        }
    )


@app.route("/export/logins", methods=["GET"])
def export_logins():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            audit_log.timestamp,
            users.username,
            users.email,
            audit_log.role,
            audit_log.action_type,
            audit_log.action,
            audit_log.source_ip,
            audit_log.user_agent,
            audit_log.severity_level
        FROM audit_log
        LEFT JOIN users ON audit_log.user_id = users.id
        WHERE audit_log.action_type IN (
            'LOGIN_SUCCESS',
            'LOGIN_FAILED',
            'REGISTER'
        )
        ORDER BY audit_log.id DESC
        """
    )

    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Timestamp",
        "Username",
        "Email",
        "Role",
        "Action Type",
        "Action",
        "Source IP",
        "User Agent",
        "Severity"
    ])

    for row in rows:
        writer.writerow([
            row["timestamp"],
            row["username"] or "Unknown",
            row["email"] or "Unknown",
            row["role"],
            row["action_type"],
            row["action"],
            row["source_ip"],
            row["user_agent"],
            row["severity_level"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=cybershield_login_audit.csv"
        }
    )


@app.route("/report/<int:scan_id>", methods=["GET"])
def generate_scan_report(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    user_id = request.args.get("user_id")

    if user_id:
        cursor.execute(
            """
            SELECT
                id,
                filename,
                file_hash,
                filesize,
                is_malicious,
                reason,
                scan_engine,
                timestamp
            FROM file_scans
            WHERE id=?
            AND user_id=?
            """,
            (
                scan_id,
                user_id
            )
        )
    else:
        cursor.execute(
            """
            SELECT
                id,
                filename,
                file_hash,
                filesize,
                is_malicious,
                reason,
                scan_engine,
                timestamp
            FROM file_scans
            WHERE id=?
            """,
            (scan_id,)
        )

    scan = cursor.fetchone()
    conn.close()

    if not scan:
        return jsonify({
            "success": False,
            "message": "Scan not found"
        }), 404

    status = (
        "Suspicious / Malicious"
        if scan["is_malicious"]
        else "Clean"
    )

    risk_text = (
        "High risk file. Manual review recommended."
        if scan["is_malicious"]
        else "Low risk file. No obvious threat indicators found."
    )

    buffer = BytesIO()

    pdf = canvas.Canvas(
        buffer,
        pagesize=A4
    )

    width, height = A4

    pdf.setTitle(
        f"CyberShield Scan Report - {scan['filename']}"
    )

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(
        50,
        height - 60,
        "CyberShield AI - Scan Report"
    )

    pdf.setFont("Helvetica", 11)
    pdf.drawString(
        50,
        height - 90,
        "Enterprise File Security Analysis"
    )

    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(
        50,
        height - 130,
        "File Information"
    )

    pdf.setFont("Helvetica", 10)

    lines = [
        f"Scan ID: {scan['id']}",
        f"Filename: {scan['filename']}",
        f"File Location: uploads/{scan['filename']}",
        f"File Size: {scan['filesize']} bytes",
        f"SHA-256: {scan['file_hash']}",
        f"Status: {status}",
        f"Reason: {scan['reason']}",
        f"Scan Engine: {scan['scan_engine']}",
        f"Scan Date: {scan['timestamp']}",
    ]

    y = height - 160

    for line in lines:
        pdf.drawString(
            50,
            y,
            line[:115]
        )
        y -= 22

    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(
        50,
        y - 15,
        "AI Risk Assessment"
    )

    pdf.setFont("Helvetica", 10)
    pdf.drawString(
        50,
        y - 45,
        risk_text
    )

    pdf.setFont("Helvetica", 8)
    pdf.drawString(
        50,
        40,
        "Generated by CyberShield AI Enterprise Security Platform"
    )

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"scan_report_{scan_id}.pdf",
        mimetype="application/pdf"
    )


@app.route("/admin/users", methods=["GET"])
def admin_get_users():
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            users.id,
            users.username,
            users.email,
            users.role,
            users.created_at,
            users.is_blocked,
            users.password,

            COUNT(DISTINCT file_scans.id) AS scan_count,

            SUM(
                CASE
                    WHEN file_scans.is_malicious=1 THEN 1
                    ELSE 0
                END
            ) AS suspicious_count,

            (
                SELECT COUNT(*)
                FROM audit_log
                WHERE audit_log.user_id = users.id
                AND audit_log.action_type='LOGIN_SUCCESS'
            ) AS login_count,

            (
                SELECT MAX(timestamp)
                FROM audit_log
                WHERE audit_log.user_id = users.id
                AND audit_log.action_type='LOGIN_SUCCESS'
            ) AS last_login

        FROM users
        LEFT JOIN file_scans ON users.id = file_scans.user_id
        GROUP BY users.id
        ORDER BY users.id DESC
        """
    )

    rows = cursor.fetchall()
    conn.close()

    users = []

    for row in rows:
        users.append({
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"],
            "created_at": row["created_at"],
            "is_blocked": row["is_blocked"],
            "password_hash_preview": row["password"][:24] + "...",
            "password_status": "Protected / Hashed",
            "scan_count": row["scan_count"] or 0,
            "suspicious_count": row["suspicious_count"] or 0,
            "login_count": row["login_count"] or 0,
            "last_login": row["last_login"] or "Never"
        })

    return jsonify(users)


@app.route("/admin/users/<int:user_id>/block", methods=["POST"])
def admin_block_user(user_id):
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET is_blocked=1
        WHERE id=?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()

    log_audit(
        user_id=admin["id"],
        action_type="ADMIN_BLOCK_USER",
        action=f"Admin blocked user ID {user_id}",
        role="admin",
        target_resource=str(user_id),
        severity_level="warning"
    )

    return jsonify({
        "success": True,
        "message": "User blocked successfully"
    })


@app.route("/admin/users/<int:user_id>/unblock", methods=["POST"])
def admin_unblock_user(user_id):
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET is_blocked=0
        WHERE id=?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()

    log_audit(
        user_id=admin["id"],
        action_type="ADMIN_UNBLOCK_USER",
        action=f"Admin unblocked user ID {user_id}",
        role="admin",
        target_resource=str(user_id),
        severity_level="info"
    )

    return jsonify({
        "success": True,
        "message": "User unblocked successfully"
    })


@app.route("/admin/users/<int:user_id>/delete", methods=["DELETE"])
def admin_delete_user(user_id):
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    if int(admin["id"]) == int(user_id):
        return jsonify({
            "success": False,
            "message": "Admin cannot delete own account"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM users
        WHERE id=?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()

    log_audit(
        user_id=admin["id"],
        action_type="ADMIN_DELETE_USER",
        action=f"Admin deleted user ID {user_id}",
        role="admin",
        target_resource=str(user_id),
        severity_level="critical"
    )

    return jsonify({
        "success": True,
        "message": "User deleted successfully"
    })


@app.route("/admin/users/<int:user_id>/report/csv", methods=["GET"])
def admin_user_report_csv(user_id):
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            email,
            role,
            created_at,
            is_blocked,
            password
        FROM users
        WHERE id=?
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    cursor.execute(
        """
        SELECT
            timestamp,
            action_type,
            action,
            source_ip,
            user_agent,
            severity_level
        FROM audit_log
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user_id,)
    )

    logs = cursor.fetchall()

    cursor.execute(
        """
        SELECT
            filename,
            file_hash,
            filesize,
            is_malicious,
            reason,
            scan_engine,
            timestamp
        FROM file_scans
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user_id,)
    )

    scans = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["USER REPORT"])
    writer.writerow(["Name", user["username"]])
    writer.writerow(["Email", user["email"]])
    writer.writerow(["Role", user["role"]])
    writer.writerow(["Created At", user["created_at"]])
    writer.writerow(["Blocked", "Yes" if user["is_blocked"] else "No"])
    writer.writerow(["Password Status", "Protected / Hashed"])
    writer.writerow(["Password Hash Preview", user["password"][:24] + "..."])
    writer.writerow([])

    writer.writerow(["LOGIN / AUDIT HISTORY"])
    writer.writerow([
        "Timestamp",
        "Action Type",
        "Action",
        "Source IP",
        "User Agent",
        "Severity"
    ])

    for log in logs:
        writer.writerow([
            log["timestamp"],
            log["action_type"],
            log["action"],
            log["source_ip"],
            log["user_agent"],
            log["severity_level"]
        ])

    writer.writerow([])
    writer.writerow(["FILE SCANS"])
    writer.writerow([
        "Filename",
        "SHA256",
        "Size",
        "Status",
        "Reason",
        "Engine",
        "Date"
    ])

    for scan in scans:
        writer.writerow([
            scan["filename"],
            scan["file_hash"],
            scan["filesize"],
            "Suspicious" if scan["is_malicious"] else "Clean",
            scan["reason"],
            scan["scan_engine"],
            scan["timestamp"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f"attachment; filename=user_{user_id}_report.csv"
        }
    )


@app.route("/admin/users/<int:user_id>/report/pdf", methods=["GET"])
def admin_user_report_pdf(user_id):
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            email,
            role,
            created_at,
            is_blocked,
            password
        FROM users
        WHERE id=?
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_log
        WHERE user_id=?
        AND action_type='LOGIN_SUCCESS'
        """,
        (user_id,)
    )

    login_count = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT
            source_ip,
            timestamp
        FROM audit_log
        WHERE user_id=?
        AND action_type='LOGIN_SUCCESS'
        ORDER BY id DESC
        LIMIT 1
        """,
        (user_id,)
    )

    last_login = cursor.fetchone()
    last_login_geo = (
        get_ip_geolocation(last_login["source_ip"])
        if last_login
        else {
            "country": "Never",
            "city": "Never",
            "isp": "Never",
            "latitude": None,
            "longitude": None,
            "location": "Never"
        }
    )

    cursor.execute(
        """
        SELECT
            filename,
            filesize,
            is_malicious,
            reason,
            timestamp
        FROM file_scans
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 10
        """,
        (user_id,)
    )

    scans = cursor.fetchall()
    conn.close()

    buffer = BytesIO()
    pdf = canvas.Canvas(
        buffer,
        pagesize=A4
    )

    width, height = A4

    pdf.setTitle(
        f"CyberShield Admin User Report - {user['username']}"
    )

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(
        50,
        height - 60,
        "CyberShield AI - Admin User Report"
    )

    pdf.setFont("Helvetica", 10)

    y = height - 100

    lines = [
        f"User ID: {user['id']}",
        f"Name: {user['username']}",
        f"Email: {user['email']}",
        f"Role: {user['role']}",
        f"Blocked: {'Yes' if user['is_blocked'] else 'No'}",
        f"Created At: {user['created_at']}",
        "Password Status: Protected / Hashed",
        f"Password Hash Preview: {user['password'][:24]}...",
        f"Login Count: {login_count}",
        f"Last Login IP: {last_login['source_ip'] if last_login else 'Never'}",
        f"Last Login Date: {last_login['timestamp'] if last_login else 'Never'}",
        f"Last Login Country: {last_login_geo['country']}",
        f"Last Login City: {last_login_geo['city']}",
        f"Last Login ISP: {last_login_geo['isp']}",
        f"Last Login Coordinates: {last_login_geo['latitude']}, {last_login_geo['longitude']}",
    ]

    for line in lines:
        pdf.drawString(50, y, line[:110])
        y -= 20

    y -= 10

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Recent Uploaded / Scanned Files")
    y -= 25

    pdf.setFont("Helvetica", 9)

    if not scans:
        pdf.drawString(50, y, "No files scanned by this user.")
    else:
        for scan in scans:
            status = (
                "Suspicious"
                if scan["is_malicious"]
                else "Clean"
            )

            text = (
                f"{scan['filename']} | {scan['filesize']} bytes | "
                f"{status} | {scan['timestamp']}"
            )

            pdf.drawString(50, y, text[:115])
            y -= 18

            if y < 70:
                pdf.showPage()
                y = height - 60
                pdf.setFont("Helvetica", 9)

    pdf.setFont("Helvetica", 8)
    pdf.drawString(
        50,
        40,
        "Generated by CyberShield AI Enterprise Admin Panel"
    )

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"user_{user_id}_admin_report.pdf",
        mimetype="application/pdf"
    )


@app.route("/admin/audit", methods=["GET"])
def admin_audit_logs():
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            audit_log.id,
            audit_log.timestamp,
            audit_log.user_id,
            audit_log.action_type,
            audit_log.role,
            audit_log.action,
            audit_log.target_resource,
            audit_log.source_ip,
            audit_log.user_agent,
            audit_log.severity_level,
            users.username,
            users.email
        FROM audit_log
        LEFT JOIN users ON audit_log.user_id = users.id
        ORDER BY audit_log.id DESC
        LIMIT 100
        """
    )

    rows = cursor.fetchall()
    conn.close()

    logs = []
    geo_cache = {}

    for row in rows:
        ip_address = row["source_ip"]

        if ip_address not in geo_cache:
            geo_cache[ip_address] = get_ip_geolocation(ip_address)

        geo = geo_cache[ip_address]

        logs.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "user_id": row["user_id"],
            "username": row["username"] or "Guest",
            "email": row["email"] or "Unknown",
            "action_type": row["action_type"],
            "role": row["role"],
            "action": row["action"],
            "target_resource": row["target_resource"],
            "source_ip": row["source_ip"],
            "country": geo["country"],
            "city": geo["city"],
            "isp": geo["isp"],
            "latitude": geo["latitude"],
            "longitude": geo["longitude"],
            "location": geo["location"],
            "user_agent": row["user_agent"],
            "severity_level": row["severity_level"]
        })

    return jsonify(logs)


@app.route("/admin/audit/export/csv", methods=["GET"])
def admin_audit_export_csv():
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            audit_log.timestamp,
            audit_log.user_id,
            users.username,
            users.email,
            audit_log.role,
            audit_log.action_type,
            audit_log.action,
            audit_log.target_resource,
            audit_log.source_ip,
            audit_log.user_agent,
            audit_log.severity_level
        FROM audit_log
        LEFT JOIN users ON audit_log.user_id = users.id
        ORDER BY audit_log.id DESC
        """
    )

    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Timestamp",
        "User ID",
        "Username",
        "Email",
        "Role",
        "Action Type",
        "Action",
        "Target Resource",
        "Source IP",
        "Country",
        "City",
        "ISP",
        "Latitude",
        "Longitude",
        "User Agent / Digital Fingerprint",
        "Severity"
    ])

    geo_cache = {}

    for row in rows:
        ip_address = row["source_ip"]

        if ip_address not in geo_cache:
            geo_cache[ip_address] = get_ip_geolocation(ip_address)

        geo = geo_cache[ip_address]

        writer.writerow([
            row["timestamp"],
            row["user_id"] or "Guest",
            row["username"] or "Guest",
            row["email"] or "Unknown",
            row["role"],
            row["action_type"],
            row["action"],
            row["target_resource"] or "-",
            row["source_ip"] or "-",
            geo["country"],
            geo["city"],
            geo["isp"],
            geo["latitude"] or "-",
            geo["longitude"] or "-",
            row["user_agent"] or "-",
            row["severity_level"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=cybershield_admin_audit_journal.csv"
        }
    )


@app.route("/admin/analytics", methods=["GET"])
def admin_analytics():
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM users")
    total_users = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE role='admin'
        """
    )
    total_admins = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE is_blocked=1
        """
    )
    blocked_users = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM file_scans")
    total_scans = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM file_scans
        WHERE is_malicious=1
        """
    )
    threats_detected = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_log
        WHERE action_type IN (
            'LOGIN_SUCCESS',
            'LOGIN_FAILED',
            'LOGIN_BLOCKED',
            'BRUTE_FORCE_BLOCK'
        )
        """
    )
    login_attempts = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_log
        WHERE action_type='LOGIN_SUCCESS'
        """
    )
    successful_logins = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_log
        WHERE action_type='LOGIN_FAILED'
        """
    )
    failed_logins = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_log
        WHERE action_type='BRUTE_FORCE_BLOCK'
        """
    )
    brute_force_blocks = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM audit_log")
    total_audit_events = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT DATE(timestamp) AS day,
               COUNT(*) AS total
        FROM audit_log
        WHERE action_type IN (
            'LOGIN_SUCCESS',
            'LOGIN_FAILED',
            'LOGIN_BLOCKED',
            'BRUTE_FORCE_BLOCK'
        )
        GROUP BY DATE(timestamp)
        ORDER BY day DESC
        LIMIT 7
        """
    )

    login_activity = [
        {
            "date": row["day"],
            "count": row["total"]
        }
        for row in cursor.fetchall()
    ]

    login_activity.reverse()

    cursor.execute(
        """
        SELECT DATE(timestamp) AS day,
               COUNT(*) AS total
        FROM file_scans
        GROUP BY DATE(timestamp)
        ORDER BY day DESC
        LIMIT 7
        """
    )

    scan_activity = [
        {
            "date": row["day"],
            "count": row["total"]
        }
        for row in cursor.fetchall()
    ]

    scan_activity.reverse()

    cursor.execute(
        """
        SELECT DATE(timestamp) AS day,
               COUNT(*) AS total
        FROM file_scans
        WHERE is_malicious=1
        GROUP BY DATE(timestamp)
        ORDER BY day DESC
        LIMIT 7
        """
    )

    threat_activity = [
        {
            "date": row["day"],
            "count": row["total"]
        }
        for row in cursor.fetchall()
    ]

    threat_activity.reverse()

    conn.close()

    return jsonify({
        "total_users": total_users,
        "total_admins": total_admins,
        "blocked_users": blocked_users,
        "total_scans": total_scans,
        "threats_detected": threats_detected,
        "login_attempts": login_attempts,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "brute_force_blocks": brute_force_blocks,
        "total_audit_events": total_audit_events,
        "login_activity": login_activity,
        "scan_activity": scan_activity,
        "threat_activity": threat_activity
    })


@app.route("/admin/security-report/pdf", methods=["GET"])
def admin_security_report_pdf():
    admin = require_admin()

    if not admin:
        return jsonify({
            "success": False,
            "message": "Admin access required"
        }), 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM users")
    total_users = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE role='admin'
        """
    )
    total_admins = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE is_blocked=1
        """
    )
    blocked_users = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM file_scans")
    total_scans = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM file_scans
        WHERE is_malicious=1
        """
    )
    threats_detected = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_log
        WHERE action_type='LOGIN_SUCCESS'
        """
    )
    successful_logins = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_log
        WHERE action_type='LOGIN_FAILED'
        """
    )
    failed_logins = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_log
        WHERE action_type='BRUTE_FORCE_BLOCK'
        """
    )
    brute_force_blocks = cursor.fetchone()["total"]

    cursor.execute(
        """
        SELECT
            filename,
            file_hash,
            filesize,
            reason,
            timestamp
        FROM file_scans
        WHERE is_malicious=1
        ORDER BY id DESC
        LIMIT 10
        """
    )
    top_risk_files = cursor.fetchall()

    cursor.execute(
        """
        SELECT
            audit_log.timestamp,
            audit_log.action_type,
            audit_log.action,
            audit_log.source_ip,
            audit_log.severity_level,
            users.username,
            users.email
        FROM audit_log
        LEFT JOIN users ON audit_log.user_id = users.id
        WHERE audit_log.severity_level IN ('warning', 'critical')
        ORDER BY audit_log.id DESC
        LIMIT 10
        """
    )
    recent_incidents = cursor.fetchall()

    conn.close()

    security_score = max(
        0,
        100 - (threats_detected * 2) - (brute_force_blocks * 5)
    )

    buffer = BytesIO()

    pdf = canvas.Canvas(
        buffer,
        pagesize=A4
    )

    width, height = A4

    pdf.setTitle("CyberShield AI Executive Security Report")

    def draw_footer(page_number):
        pdf.setFont("Helvetica", 8)
        pdf.drawString(
            50,
            35,
            "Generated by CyberShield AI Enterprise Security Platform"
        )
        pdf.drawRightString(
            width - 50,
            35,
            f"Page {page_number}"
        )

    page = 1

    pdf.setFont("Helvetica-Bold", 22)
    pdf.drawString(
        50,
        height - 60,
        "CyberShield AI"
    )

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(
        50,
        height - 90,
        "Executive Security Report"
    )

    pdf.setFont("Helvetica", 10)
    pdf.drawString(
        50,
        height - 115,
        "Enterprise overview of platform security posture, incidents and recommendations."
    )

    y = height - 160

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(
        50,
        y,
        "Security Summary"
    )

    y -= 30

    pdf.setFont("Helvetica", 10)

    summary_lines = [
        f"Total Users: {total_users}",
        f"Total Admins: {total_admins}",
        f"Blocked Users: {blocked_users}",
        f"Total File Scans: {total_scans}",
        f"Threats Detected: {threats_detected}",
        f"Successful Logins: {successful_logins}",
        f"Failed Logins: {failed_logins}",
        f"Brute Force Blocks: {brute_force_blocks}",
        f"Security Score: {security_score}%",
    ]

    for line in summary_lines:
        pdf.drawString(
            60,
            y,
            line
        )
        y -= 20

    y -= 15

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(
        50,
        y,
        "Executive Assessment"
    )

    y -= 25
    pdf.setFont("Helvetica", 10)

    if threats_detected == 0 and brute_force_blocks == 0:
        assessment = (
            "The current security posture is healthy. No major malware or brute force "
            "incidents were detected in the available logs."
        )
    elif threats_detected > 0 or brute_force_blocks > 0:
        assessment = (
            "The system detected security-relevant events. Administrator review is "
            "recommended for suspicious files, blocked users and failed authentication attempts."
        )
    else:
        assessment = (
            "The security posture requires periodic review using audit logs and reports."
        )

    for chunk_start in range(0, len(assessment), 95):
        pdf.drawString(
            60,
            y,
            assessment[chunk_start:chunk_start + 95]
        )
        y -= 18

    draw_footer(page)
    pdf.showPage()
    page += 1

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(
        50,
        height - 60,
        "Recent High-Risk Files"
    )

    y = height - 95
    pdf.setFont("Helvetica", 9)

    if not top_risk_files:
        pdf.drawString(
            50,
            y,
            "No suspicious or malicious files found."
        )
    else:
        for scan in top_risk_files:
            lines = [
                f"Filename: {scan['filename']}",
                f"Size: {scan['filesize']} bytes | Date: {scan['timestamp']}",
                f"SHA-256: {scan['file_hash']}",
                f"Reason: {scan['reason']}",
            ]

            for line in lines:
                pdf.drawString(
                    50,
                    y,
                    str(line)[:120]
                )
                y -= 16

            y -= 10

            if y < 80:
                draw_footer(page)
                pdf.showPage()
                page += 1
                y = height - 60
                pdf.setFont("Helvetica", 9)

    draw_footer(page)
    pdf.showPage()
    page += 1

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(
        50,
        height - 60,
        "Recent Security Incidents"
    )

    y = height - 95
    pdf.setFont("Helvetica", 9)

    if not recent_incidents:
        pdf.drawString(
            50,
            y,
            "No warning or critical incidents found."
        )
    else:
        for incident in recent_incidents:
            geo = get_ip_geolocation(incident["source_ip"])

            lines = [
                f"Date: {incident['timestamp']}",
                f"User: {incident['username'] or 'Guest'} | Email: {incident['email'] or 'Unknown'}",
                f"Action Type: {incident['action_type']} | Severity: {incident['severity_level']}",
                f"Action: {incident['action']}",
                f"Source IP: {incident['source_ip']} | Location: {geo['location']}",
            ]

            for line in lines:
                pdf.drawString(
                    50,
                    y,
                    str(line)[:120]
                )
                y -= 16

            y -= 10

            if y < 80:
                draw_footer(page)
                pdf.showPage()
                page += 1
                y = height - 60
                pdf.setFont("Helvetica", 9)

    draw_footer(page)
    pdf.showPage()
    page += 1

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(
        50,
        height - 60,
        "Security Recommendations"
    )

    y = height - 95
    pdf.setFont("Helvetica", 10)

    recommendations = [
        "Review suspicious and malicious files before allowing users to download or execute them.",
        "Keep brute force protection enabled and investigate repeated failed login attempts.",
        "Use the Admin Panel to block suspicious accounts and document the action in audit logs.",
        "Export CSV audit logs periodically for evidence and compliance.",
        "Use PDF reports for incident response, academic presentation and executive summaries.",
        "Keep VirusTotal API key and email App Password stored securely, not directly in public repositories.",
        "Review IP geolocation indicators for unusual login sources.",
    ]

    for index, recommendation in enumerate(recommendations, start=1):
        text = f"{index}. {recommendation}"

        for chunk_start in range(0, len(text), 105):
            pdf.drawString(
                50,
                y,
                text[chunk_start:chunk_start + 105]
            )
            y -= 18

        y -= 5

        if y < 80:
            draw_footer(page)
            pdf.showPage()
            page += 1
            y = height - 60
            pdf.setFont("Helvetica", 10)

    draw_footer(page)

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="cybershield_executive_security_report.pdf",
        mimetype="application/pdf"
    )



@app.route("/")
def home():
    return jsonify({
        "status": "CyberShield Enterprise API Running",
        "database": DATABASE,
        "virustotal_enabled": bool(VIRUSTOTAL_API_KEY),
        "email_alerts_enabled": bool(EMAIL_SENDER and EMAIL_PASSWORD),
        "brute_force_protection": True,
        "max_failed_login_attempts": MAX_FAILED_LOGIN_ATTEMPTS,
        "exports": [
            "/export/scans",
            "/export/logins"
        ],
        "reports": "/report/<scan_id>",
        "admin": [
            "/admin/users",
            "/admin/users/<id>/block",
            "/admin/users/<id>/unblock",
            "/admin/users/<id>/delete",
            "/admin/users/<id>/report/csv",
            "/admin/users/<id>/report/pdf",
            "/admin/audit",
            "/admin/audit/export/csv",
            "/admin/analytics",
            "/admin/security-report/pdf"
        ]
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )