import os
import base64
import json
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv
from logger import log_event  # logarea evenimentelor de criptare/decriptare

load_dotenv()

# === Load encryption keys ===
key_versions = ["1", "2", "3"]
keys = {}

for version in key_versions:
    env_key = os.getenv(f"ENCRYPTION_KEY_V{version}")
    if not env_key:
        raise RuntimeError(f"❌ Missing ENCRYPTION_KEY_V{version} in .env!")
    keys[version] = hashlib.sha256(env_key.encode()).digest()

current_version = os.getenv("ENCRYPTION_KEY_VERSION", "1")
current_key = keys.get(current_version)

if not current_key:
    raise RuntimeError("❌ Invalid ENCRYPTION_KEY_VERSION in .env!")

class AESCipher:
    def __init__(self, key=current_key):
        self.key = key
        self.bs = AES.block_size

    def encrypt(self, raw: str) -> str:
        try:
            raw_padded = pad(raw.encode('utf-8'), self.bs)
            iv = get_random_bytes(self.bs)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(raw_padded)

            # Compute HMAC for integrity
            mac = hmac.new(self.key, iv + ciphertext, hashlib.sha256).digest()

            payload = {
                "version": current_version,
                "iv": base64.b64encode(iv).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "mac": base64.b64encode(mac).decode()
            }
            return base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')

        except Exception as e:
            log_event("encryption_failed", metadata={"error": str(e)})
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt(self, enc: str) -> str:
        try:
            payload = json.loads(base64.b64decode(enc).decode('utf-8'))
            version = payload.get("version", "1")
            key = keys.get(version)
            if not key:
                raise Exception("Unsupported encryption key version.")

            iv = base64.b64decode(payload["iv"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            mac = base64.b64decode(payload["mac"])

            # Verify HMAC before decryption
            expected_mac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                log_event("decryption_mac_failed")
                raise Exception("Invalid MAC! Possible data tampering detected.")

            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted_padded, self.bs)
            return decrypted.decode('utf-8')

        except Exception as e:
            log_event("decryption_failed", metadata={"error": str(e)})
            raise Exception(f"Decryption failed: {str(e)}")
