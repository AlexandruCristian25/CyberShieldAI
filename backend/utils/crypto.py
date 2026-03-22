import os
import base64
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

VERSION_PREFIX = b"CRYPTOV1"

def _derive_keys(secret: str):
    key = hashlib.sha256(secret.encode()).digest()
    encryption_key = key[:16]  # primii 16 bytes pentru AES
    hmac_key = key[16:]        # restul pentru HMAC
    return encryption_key, hmac_key

def loop_encrypt(data: str, loops: int = 2) -> str:
    secret = os.getenv("ENCRYPTION_KEY")
    if not secret:
        raise ValueError("Missing ENCRYPTION_KEY in environment")

    enc_key, hmac_key = _derive_keys(secret)
    result = data.encode()

    for _ in range(loops):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        result = iv + cipher.encrypt(pad(result, AES.block_size))

    mac = hmac.new(hmac_key, result, digestmod=hashlib.sha256).digest()
    payload = VERSION_PREFIX + mac + result
    return base64.b64encode(payload).decode()

def loop_decrypt(encoded_data: str, loops: int = 2, alt_secret: Optional[str] = None) -> Optional[str]:
    try:
        raw = base64.b64decode(encoded_data)
        if not raw.startswith(VERSION_PREFIX):
            return None
        raw = raw[len(VERSION_PREFIX):]

        mac_provided = raw[:32]
        data = raw[32:]

        # Alegem cheia de decrypt
        secret = alt_secret or os.getenv("ENCRYPTION_KEY")
        if not secret:
            raise ValueError("Missing ENCRYPTION_KEY in environment")

        enc_key, hmac_key = _derive_keys(secret)

        expected_mac = hmac.new(hmac_key, data, digestmod=hashlib.sha256).digest()
        if not hmac.compare_digest(mac_provided, expected_mac):
            return None

        result = data
        for _ in range(loops):
            iv = result[:16]
            ct = result[16:]
            cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
            result = unpad(cipher.decrypt(ct), AES.block_size)

        return result.decode("utf-8")

    except Exception:
        # Opțional: logare pentru audit
        # logger.log_error("Decryption failed")
        return None
