import os
import hashlib
import mimetypes
import magic
import requests
from datetime import datetime
from logger import log_event, log_error
from notifier import send_suspicious_login_alert
from db import get_db_connection

# Setări VirusTotal
VT_API_KEY = "YOUR_REAL_VIRUSTOTAL_API_KEY"
VT_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_REPORT_URL = "https://www.virustotal.com/api/v3/files/{}"

# Listă extensii periculoase cunoscute
DANGEROUS_EXTENSIONS = {'.exe', '.bat', '.cmd', '.sh', '.js', '.vbs', '.jar', '.scr'}

# Mime types suspecte (execuție, scripting, etc.)
DANGEROUS_MIME_TYPES = {
    'application/x-msdownload', 'application/x-sh', 'application/javascript',
    'application/x-dosexec', 'application/x-executable', 'application/x-msdos-program',
    'application/x-bat', 'application/vnd.microsoft.portable-executable'
}

# Hashuri cunoscute (exemplu demonstrativ, poate fi populat dintr-o bază de date reală)
KNOWN_BAD_HASHES = {
    "badexamplehash1234567890abcdef1234567890abcdef1234567890abcdef12345678"
}

# Whitelist (hash-uri considerate sigure)
WHITELIST_HASHES = set()

def get_file_hash(file_path):
    """Calculează SHA-256 hash pentru un fișier."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        log_error(f"Error hashing file {file_path}: {e}")
        return None

def scan_with_virustotal(file_path, file_hash):
    headers = {"x-apikey": VT_API_KEY}
    report = requests.get(VT_REPORT_URL.format(file_hash), headers=headers)
    if report.status_code == 200:
        data = report.json()
        stats = data['data']['attributes']['last_analysis_stats']
        if stats['malicious'] > 0:
            return True, "VirusTotal malicious"
        return False, "VirusTotal clean"
    elif report.status_code == 404:
        # Upload for scanning
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(VT_SCAN_URL, headers=headers, files=files)
            if response.status_code == 200:
                log_event("[INFO] File uploaded to VirusTotal for analysis.")
                return False, "VirusTotal scan pending"
    return False, "VirusTotal unavailable"

def log_scan_to_db(file_path, user=None, is_malicious=False, reason="N/A"):
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO file_scans (filename, user, is_malicious, reason, timestamp)
            VALUES (?, ?, ?, ?, ?)""",
        (os.path.basename(file_path), user, int(is_malicious), reason, datetime.utcnow())
    )
    conn.commit()

def is_malicious(file_path, user=None):
    """Verifică dacă un fișier este potențial periculos."""
    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in DANGEROUS_EXTENSIONS:
            reason = f"Dangerous extension: {ext}"
            log_event(f"[ALERT] {reason}")
            log_scan_to_db(file_path, user, True, reason)
            send_suspicious_login_alert("admin@cybershield.ai", f"{file_path} - {reason}")
            return True

        mime_type = magic.from_file(file_path, mime=True)
        if mime_type in DANGEROUS_MIME_TYPES:
            reason = f"Suspicious MIME type: {mime_type}"
            log_event(f"[ALERT] {reason}")
            log_scan_to_db(file_path, user, True, reason)
            send_suspicious_login_alert("admin@cybershield.ai", f"{file_path} - {reason}")
            return True

        file_hash = get_file_hash(file_path)
        if not file_hash:
            log_scan_to_db(file_path, user, True, "Failed to hash file")
            return True

        if file_hash in WHITELIST_HASHES:
            log_scan_to_db(file_path, user, False, "Whitelisted")
            return False

        if file_hash in KNOWN_BAD_HASHES:
            reason = "Known bad hash"
            log_event(f"[ALERT] {reason}: {file_hash}")
            log_scan_to_db(file_path, user, True, reason)
            send_suspicious_login_alert("admin@cybershield.ai", f"{file_path} - {reason}")
            return True

        vt_malicious, vt_reason = scan_with_virustotal(file_path, file_hash)
        log_scan_to_db(file_path, user, vt_malicious, vt_reason)
        return vt_malicious

    except Exception as e:
        log_error(f"[SCAN_ERROR] Failed to scan {file_path}: {e}")
        log_scan_to_db(file_path, user, True, "Exception during scan")
        return True
