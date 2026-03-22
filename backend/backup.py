from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os
import time

BACKUP_DIR = "backups"
SALT = b"CyberShieldBackupSalt"  # static salt (sau poate fi randomizat per deployment)

def derive_key(secret: str) -> bytes:
    """Derive a 256-bit key from a passphrase."""
    return PBKDF2(secret, SALT, dkLen=32, count=100_000)

def encrypt_file(in_file: str, out_file: str, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    with open(in_file, "rb") as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(out_file, "wb") as f:
        f.write(cipher.nonce + tag + ciphertext)

def ensure_backup_dir():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

if __name__ == "__main__":
    start = time.time()

    secret = os.getenv("BACKUP_KEY")
    if not secret:
        raise ValueError("BACKUP_KEY not found in environment variables")
    
    key = derive_key(secret)

    ensure_backup_dir()

    in_file = "file_scans.db"
    out_file = os.path.join(BACKUP_DIR, "file_scans_backup.enc")

    encrypt_file(in_file, out_file, key)

    size = os.path.getsize(out_file) / 1024
    runtime = round(time.time() - start, 2)
    print(f"🔐 Backup criptat creat ({size:.2f} KB) în {runtime} secunde.")
