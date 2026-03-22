import os
import time
import io
import joblib
import pandas as pd
import logging
from pathlib import Path
from explainability import explain_model_prediction
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet
from threading import Lock

# Configurare logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Director modele criptate
MODEL_DIR = Path("models/").resolve()
# Feature-uri permise
ALLOWED_FEATURES = {"age", "income", "gender", "location", "purchase_history"}

# Autentificare și criptare
AUTH_TOKEN = os.getenv("EXPLAIN_AUTH_TOKEN")
FERNET_KEY = os.getenv("MODEL_FERNET_KEY")
if not FERNET_KEY:
    logger.error("MODEL_FERNET_KEY nu configurată")
    raise RuntimeError("Lipsește MODEL_FERNET_KEY")
fernet = Fernet(FERNET_KEY.encode())

# Configurări rate limiting și backoff
RATE_LIMIT_MAX_CALLS = int(os.getenv("RATE_LIMIT_MAX_CALLS", 5))
RATE_LIMIT_PERIOD = int(os.getenv("RATE_LIMIT_PERIOD", 60))
RATE_LIMIT_ALGO = os.getenv("RATE_LIMIT_ALGO", "sliding").lower()
BACKOFF_INITIAL = float(os.getenv("RATE_LIMIT_BACKOFF_INITIAL", 1))
BACKOFF_MULTIPLIER = float(os.getenv("RATE_LIMIT_BACKOFF_MULTIPLIER", 2))
BACKOFF_MAX = float(os.getenv("RATE_LIMIT_BACKOFF_MAX", 60))

# Sliding Window Limiter
class SlidingWindowLimiter:
    def __init__(self, max_calls: int, period: int):
        self.max_calls = max_calls
        self.period = period
        self.calls: list[float] = []
        self.lock = Lock()

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            with self.lock:
                now = time.time()
                self.calls = [t for t in self.calls if now - t < self.period]
                if len(self.calls) >= self.max_calls:
                    logger.warning("Sliding window: limit atins")
                    raise RuntimeError("Prea multe cereri. Încearcă din nou mai târziu.")
                self.calls.append(now)
            return func(*args, **kwargs)
        return wrapper

# Token Bucket Limiter
class TokenBucketLimiter:
    def __init__(self, capacity: int, period: int):
        self.capacity = capacity
        self.tokens = capacity
        self.period = period
        self.last_refill = time.time()
        self.lock = Lock()

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            with self.lock:
                now = time.time()
                elapsed = now - self.last_refill
                refill = (elapsed * self.capacity) / self.period
                if refill > 0:
                    self.tokens = min(self.capacity, self.tokens + refill)
                    self.last_refill = now
                if self.tokens < 1:
                    logger.warning("Token bucket: acces blocat")
                    raise RuntimeError("Prea multe cereri. Încearcă din nou mai târziu.")
                self.tokens -= 1
            return func(*args, **kwargs)
        return wrapper

# Exponential Backoff Limiter
class ExponentialBackoffLimiter:
    def __init__(self, base_delay: float, multiplier: float, max_delay: float):
        self.base = base_delay
        self.multiplier = multiplier
        self.max = max_delay
        self.last_call = 0.0
        self.violation_count = 0
        self.lock = Lock()

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            with self.lock:
                now = time.time()
                # Interval minimal între apeluri
                min_interval = RATE_LIMIT_PERIOD / max(RATE_LIMIT_MAX_CALLS, 1)
                if now - self.last_call < min_interval:
                    self.violation_count += 1
                    backoff = min(self.base * (self.multiplier ** (self.violation_count - 1)), self.max)
                    logger.warning("Backoff: așteaptă %s secunde", backoff)
                    raise RuntimeError(f"Prea multe cereri. Așteaptă {backoff:.1f}s înainte de retry.")
                # Reset la apel valid
                self.violation_count = 0
                self.last_call = now
            return func(*args, **kwargs)
        return wrapper

# IP-Based Limiter
class IPBasedLimiter:
    def __init__(self, max_calls: int, period: int):
        self.max_calls = max_calls
        self.period = period
        self.calls: Dict[str, list[float]] = {}
        self.lock = Lock()

    def __call__(self, func):
        def wrapper(*args, ip_address: Optional[str] = None, **kwargs):
            if not ip_address:
                raise ValueError("IP-based rate limiting necesită parametrul ip_address.")
            with self.lock:
                now = time.time()
                history = self.calls.get(ip_address, [])
                history = [t for t in history if now - t < self.period]
                if len(history) >= self.max_calls:
                    logger.warning("IP %s a atins rata limită", ip_address)
                    raise RuntimeError("Prea multe cereri de la IP-ul tău. Încearcă mai târziu.")
                history.append(now)
                self.calls[ip_address] = history
            return func(*args, **kwargs)
        return wrapper

# Alegere limiter din configurări
if RATE_LIMIT_ALGO == 'token':
    limiter = TokenBucketLimiter(RATE_LIMIT_MAX_CALLS, RATE_LIMIT_PERIOD)
elif RATE_LIMIT_ALGO == 'backoff':
    limiter = ExponentialBackoffLimiter(BACKOFF_INITIAL, BACKOFF_MULTIPLIER, BACKOFF_MAX)
elif RATE_LIMIT_ALGO == 'ip':
    limiter = IPBasedLimiter(RATE_LIMIT_MAX_CALLS, RATE_LIMIT_PERIOD)
else:
    limiter = SlidingWindowLimiter(RATE_LIMIT_MAX_CALLS, RATE_LIMIT_PERIOD)

@limiter
def run_explainability(model_path: str,
                       sample_dict: Dict[str, Any],
                       auth_token: str,
                       ip_address: Optional[str] = None) -> Dict[str, Any]:
    """
    Încarcă un model criptat, validează autentificarea și generează o explicație SHAP.

    Args:
        model_path: Relativ din MODEL_DIR către fișierul .pkl.enc
        sample_dict: Dicționar cu feature-uri de intrare
        auth_token: Token valid de autentificare
        ip_address: Opțional, necesar pentru RATE_LIMIT_ALGO='ip'
    Returns:
        {'summary_base64', 'text_explanation'} sau {'error'}
    """
    try:
        # Autentificare
        if not AUTH_TOKEN or auth_token != AUTH_TOKEN:
            logger.error("Token invalid: %s", auth_token)
            raise PermissionError("Token de autentificare invalid.")

        # Validare input
        if not isinstance(sample_dict, dict) or not sample_dict:
            raise ValueError("sample_dict trebuie să fie un dicționar ne-gol.")
        invalid = set(sample_dict.keys()) - ALLOWED_FEATURES
        if invalid:
            raise ValueError(f"Feature-uri nepermise: {invalid}")

        # Încărcare și decriptare model
        raw = Path(model_path)
        enc_file = (MODEL_DIR / raw).resolve()
        if not enc_file.exists() or not enc_file.is_file():
            raise FileNotFoundError(f"Model inexistent: {enc_file}")
        if MODEL_DIR not in enc_file.parents:
            raise PermissionError("Acces interzis la model.")

        encrypted = enc_file.read_bytes()
        try:
            decrypted = fernet.decrypt(encrypted)
        except Exception as e:
            logger.error("Decriptare eșuată: %s", e)
            raise RuntimeError("Nu s-a putut decripta modelul.")

        model = joblib.load(io.BytesIO(decrypted))

        # Generare explicație
        df = pd.DataFrame([sample_dict])
        summary_base64, text_exp = explain_model_prediction(
            model=model, X=df, feature_names=list(sample_dict.keys())
        )
        if not summary_base64 or not text_exp:
            raise RuntimeError("Eșec generație explicație SHAP.")

        logger.info("Explicație generată cu succes.")
        return {"summary_base64": summary_base64, "text_explanation": text_exp}
    except Exception as e:
        logger.error("Eroare run_explainability: %s", e)
        return {"error": str(e)}
