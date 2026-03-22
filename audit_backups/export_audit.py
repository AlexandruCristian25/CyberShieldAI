import argparse
import hmac
import base64
import hashlib
import logging
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

# Load .env
load_dotenv()

# === CONFIG ===
KEY_AES = base64.b64decode(os.getenv("AES_SECRET_KEY"))
KEY_HMAC = base64.b64decode(os.getenv("HMAC_SECRET_KEY"))

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')

# === UTILS ===
def decrypt_data(encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(KEY_AES), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

def verify_hmac(encrypted_data: bytes, signature_file: Path) -> bool:
    with open(signature_file, "r") as f:
        sig_content = f.read()
    timestamp, signature = sig_content.split("::")
    expected_hmac = hmac.new(KEY_HMAC, timestamp.encode() + encrypted_data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected_hmac)

# === MAIN FUNCTION ===
def decrypt_audit_file(enc_file_path: str, sig_file_path: str, output_csv_path: str):
    try:
        encrypted_data = Path(enc_file_path).read_bytes()

        if not verify_hmac(encrypted_data, Path(sig_file_path)):
            logging.error("⚠️ Semnătura HMAC nu corespunde. Fișier compromis!")
            return

        decrypted_data = decrypt_data(encrypted_data)
        Path(output_csv_path).write_bytes(decrypted_data)
        logging.info(f"✅ Fișier decriptat cu succes: {output_csv_path}")

    except Exception as e:
        logging.error(f"❌ Eroare la decriptare: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decriptează și verifică un fișier de audit.")
    parser.add_argument("-i", "--input", required=True, help="Fișierul criptat (.enc)")
    parser.add_argument("-s", "--signature", required=True, help="Fișierul semnătură (.sig)")
    parser.add_argument("-o", "--output", required=True, help="Fișierul de ieșire CSV")
    args = parser.parse_args()
    decrypt_audit_file(args.input, args.signature, args.output)
