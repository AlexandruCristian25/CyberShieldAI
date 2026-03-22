from datetime import datetime, timedelta
from threading import Lock
import re
from flask import request, jsonify
from logger import log_event, log_error
from notifier import send_suspicious_login_alert
from db import get_db_connection
import redis

# Redis setup (global rate limiting)
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
GLOBAL_RATE_LIMIT = 100  # max requests
RATE_LIMIT_WINDOW = 60   # in seconds

# Securitate configurabilă
MAX_ATTEMPTS = 5
BLOCK_TIME_MINUTES = 15

# Structuri în memorie + lock pentru siguranță
login_attempts_ip = {}
login_attempts_user = {}
block_list_ip = {}
block_list_user = {}
lock = Lock()

def sanitize_ip(ip: str) -> str:
    return re.sub(r"[^0-9a-fA-F.:]", "", ip.strip())[:64]

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        raw_ip = request.headers['X-Forwarded-For'].split(',')[0]
        return sanitize_ip(raw_ip)
    return sanitize_ip(request.remote_addr)

def log_block_event(ip=None, username=None):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO blocked_events (ip, username, timestamp) VALUES (?, ?, ?)",
        (ip, username, datetime.utcnow())
    )
    conn.commit()
    if ip:
        send_suspicious_login_alert("admin@cybershield.ai", ip)

def is_blocked(ip: str, username: str) -> bool:
    now = datetime.now()
    with lock:
        if ip in block_list_ip and now < block_list_ip[ip]:
            return True
        if username in block_list_user and now < block_list_user[username]:
            return True
    return False

def register_failed_attempt(ip: str, username: str):
    now = datetime.now()
    with lock:
        # Per IP
        ip_attempts = login_attempts_ip.setdefault(ip, [])
        ip_attempts = [a for a in ip_attempts if now - a < timedelta(minutes=BLOCK_TIME_MINUTES)]
        ip_attempts.append(now)
        login_attempts_ip[ip] = ip_attempts

        if len(ip_attempts) >= MAX_ATTEMPTS:
            block_list_ip[ip] = now + timedelta(minutes=BLOCK_TIME_MINUTES)
            log_event(f"[SECURITY] IP blocked: {ip}")
            log_block_event(ip=ip)

        # Per User
        if username:
            user_attempts = login_attempts_user.setdefault(username, [])
            user_attempts = [a for a in user_attempts if now - a < timedelta(minutes=BLOCK_TIME_MINUTES)]
            user_attempts.append(now)
            login_attempts_user[username] = user_attempts

            if len(user_attempts) >= MAX_ATTEMPTS:
                block_list_user[username] = now + timedelta(minutes=BLOCK_TIME_MINUTES)
                log_event(f"[SECURITY] User blocked: {username}")
                log_block_event(username=username)

def check_global_rate_limit(ip):
    key = f"rate_limit:{ip}"
    current = r.incr(key)
    if current == 1:
        r.expire(key, RATE_LIMIT_WINDOW)
    if current > GLOBAL_RATE_LIMIT:
        return False
    return True

# Exemplar: integrare în endpoint
from flask import Blueprint
security_bp = Blueprint('security', __name__)

@security_bp.route('/login', methods=['POST'])
def login():
    ip = get_client_ip()
    username = request.form.get('username', '')

    if not check_global_rate_limit(ip):
        log_event(f"[RATE LIMIT] IP {ip} exceeded global rate limit.")
        return jsonify({"error": "Too many requests. Try again later."}), 429

    if is_blocked(ip, username):
        return jsonify({"error": "Your access has been temporarily blocked."}), 403

    # Autentificare fictivă (de înlocuit cu logica reală)
    password = request.form.get('password', '')
    if username != 'admin' or password != 'password123':
        register_failed_attempt(ip, username)
        return jsonify({"error": "Invalid credentials."}), 401

    return jsonify({"message": "Login successful."}), 200
