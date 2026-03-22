import os
import secrets
import shutil
from datetime import datetime
from dotenv import load_dotenv
from typing import Optional

ENV_FILE = ".env"
BACKUP_DIR = "backups"
ROTATIONS_DIR = "backups/rotations"
ROTATED_KEY_VAR = "ENCRYPTION_KEY"

def generate_secure_key(length=64):
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(secrets.choice(charset) for _ in range(length))

def backup_env() -> str:
    os.makedirs(ROTATIONS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(ROTATIONS_DIR, f".env.backup_{timestamp}")
    shutil.copy2(ENV_FILE, backup_path)
    print(f"[+] Backup saved to {backup_path}")
    return backup_path

def restore_last_backup() -> Optional[str]:
    try:
        backups = sorted([
            f for f in os.listdir(ROTATIONS_DIR)
            if f.startswith(".env.backup_")
        ], reverse=True)
        if not backups:
            print("[!] No backup found.")
            return None
        latest = os.path.join(ROTATIONS_DIR, backups[0])
        shutil.copy2(latest, ENV_FILE)
        print(f"[✓] Restored backup from {latest}")
        return latest
    except Exception as e:
        print(f"[!] Restore failed: {e}")
        return None

def update_env_variable(key, value):
    load_dotenv(ENV_FILE)
    updated = False
    lines = []

    with open(ENV_FILE, "r") as f:
        for line in f:
            if line.strip().startswith(f"{key}="):
                lines.append(f"{key}={value}\n")
                updated = True
            else:
                lines.append(line)

    if not updated:
        lines.append(f"{key}={value}\n")

    # Scriere sigură: write + rename atomic
    temp_file = ENV_FILE + ".tmp"
    with open(temp_file, "w") as f:
        f.writelines(lines)
    os.replace(temp_file, ENV_FILE)

def verify_env_syntax() -> bool:
    try:
        load_dotenv(ENV_FILE, override=True)
        key = os.getenv(ROTATED_KEY_VAR)
        assert key and len(key) > 30
        return True
    except Exception as e:
        print(f"[!] ENV verification failed: {e}")
        return False

def rotate_key(force=False, interactive=False):
    if interactive:
        confirm = input("[?] Are you sure you want to rotate the encryption key? (y/n): ")
        if confirm.strip().lower() != "y":
            print("[x] Operation cancelled.")
            return

    print("[*] Rotating encryption key...")
    backup_path = backup_env()
    new_key = generate_secure_key(100)
    update_env_variable(ROTATED_KEY_VAR, new_key)

    if verify_env_syntax():
        print(f"[✓] New secure {ROTATED_KEY_VAR} generated and stored in .env.")
    else:
        print("[!] Syntax error after key update. Attempting restore...")
        restored = restore_last_backup()
        if restored:
            print(f"[✓] .env restored from {restored}")
        else:
            print("[x] Manual intervention required.")

if __name__ == "__main__":
    rotate_key(interactive=True)
