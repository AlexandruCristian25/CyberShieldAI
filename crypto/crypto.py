import os
import base64
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha256
import hmac
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("AESCipher")
logger.setLevel(logging.INFO)

class AESCipher:
    VERSION_PREFIX = b"AESC1"
    BUFFER_SIZE = 4096  # pentru fișiere mari

    def __init__(self, secret_key: str):
        if not secret_key:
            raise ValueError("Secret key is missing.")
        self.bs = AES.block_size
        self.key = PBKDF2(secret_key, salt=b'CyberShieldSalt', dkLen=32, count=100_000)
        self.enc_key = self.key[:16]
        self.mac_key = self.key[16:]

    @classmethod
    def from_env(cls):
        key = os.getenv("ENCRYPTION_KEY")
        if not key:
            raise EnvironmentError("ENCRYPTION_KEY not set in environment.")
        return cls(key)

    def _pad(self, data: bytes) -> bytes:
        pad_len = self.bs - len(data) % self.bs
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > self.bs:
            raise ValueError("Invalid padding.")
        return data[:-pad_len]

    def encrypt(self, plaintext: str) -> str:
        iv = get_random_bytes(self.bs)
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
        padded = self._pad(plaintext.encode())
        encrypted = cipher.encrypt(padded)
        payload = iv + encrypted
        mac = hmac.new(self.mac_key, payload, digestmod=sha256).digest()
        full_data = self.VERSION_PREFIX + mac + payload
        return base64.b64encode(full_data).decode()

    def decrypt(self, ciphertext_b64: str) -> str:
        try:
            raw = base64.b64decode(ciphertext_b64)
            if not raw.startswith(self.VERSION_PREFIX):
                raise ValueError("Invalid version or corrupted data.")
            raw = raw[len(self.VERSION_PREFIX):]
            mac_received = raw[:32]
            payload = raw[32:]

            expected_mac = hmac.new(self.mac_key, payload, digestmod=sha256).digest()
            if not hmac.compare_digest(mac_received, expected_mac):
                raise ValueError("Data integrity check failed.")

            iv = payload[:self.bs]
            encrypted_data = payload[self.bs:]
            cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_data)
            return self._unpad(decrypted).decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Decryption failed.")

    def encrypt_file(self, in_path: str, out_path: str):
        iv = get_random_bytes(self.bs)
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
        mac = hmac.new(self.mac_key, digestmod=sha256)

        with open(in_path, "rb") as f_in, open(out_path, "wb") as f_out:
            f_out.write(self.VERSION_PREFIX)
            f_out.write(iv)

            while chunk := f_in.read(self.BUFFER_SIZE):
                if len(chunk) % self.bs != 0:
                    chunk = self._pad(chunk)
                encrypted = cipher.encrypt(chunk)
                mac.update(encrypted)
                f_out.write(encrypted)

            tag = mac.digest()
            f_out.seek(len(self.VERSION_PREFIX))
            f_out.write(iv + tag)

    def decrypt_file(self, in_path: str, out_path: str):
        with open(in_path, "rb") as f_in:
            version = f_in.read(len(self.VERSION_PREFIX))
            if version != self.VERSION_PREFIX:
                raise ValueError("Invalid version or corrupted file.")

            iv = f_in.read(self.bs)
            mac_received = f_in.read(32)

            cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
            mac = hmac.new(self.mac_key, digestmod=sha256)

            with open(out_path, "wb") as f_out:
                while chunk := f_in.read(self.BUFFER_SIZE):
                    mac.update(chunk)
                    decrypted = cipher.decrypt(chunk)
                    f_out.write(decrypted)

            if not hmac.compare_digest(mac.digest(), mac_received):
                raise ValueError("File integrity check failed.")

            # Final unpad
            with open(out_path, "rb+") as f_out:
                f_out.seek(0, os.SEEK_END)
                size = f_out.tell()
                f_out.seek(size - 1)
                pad_len = f_out.read(1)[0]
                f_out.truncate(size - pad_len)
