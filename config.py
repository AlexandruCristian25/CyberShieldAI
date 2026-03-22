import os
from dotenv import load_dotenv

load_dotenv()

def get_env(name: str, default=None, required: bool = True, cast_type=str):
    value = os.getenv(name, default)
    if required and (value is None or (isinstance(value, str) and value.strip() == "")):
        raise EnvironmentError(f"[CONFIG ERROR] Variabila de mediu lipsă sau goală: {name}")
    try:
        return cast_type(value) if value is not None else value
    except ValueError:
        raise ValueError(f"[CONFIG ERROR] {name} trebuie să fie de tip {cast_type.__name__}")

# ----------------------- DATABASE CONFIG -----------------------
DB_CONFIG = {
    "host": get_env("DB_HOST"),
    "port": get_env("DB_PORT", default=5432, cast_type=int),
    "dbname": get_env("DB_NAME"),
    "user": get_env("DB_USER"),
    "password": get_env("DB_PASSWORD")
}

SQLITE_URL = get_env("SQLITE_URL", default="sqlite:///security.db", required=False)

# ------------------------ SMTP CONFIG --------------------------
SMTP_CONFIG = {
    "server": get_env("SMTP_SERVER"),
    "port": get_env("SMTP_PORT", cast_type=int),
    "username": get_env("SMTP_USERNAME"),
    "password": get_env("SMTP_PASSWORD"),
    "use_tls": get_env("SMTP_USE_TLS", default="true", cast_type=str).lower() == "true"
}

# ------------------------ SECURITY CONFIG ----------------------
SECURITY_CONFIG = {
    "secret_key": get_env("SECRET_KEY"),
    "jwt_algorithm": get_env("JWT_ALGORITHM", default="HS256"),
    "jwt_expiration_seconds": get_env("JWT_EXPIRATION_DELTA", default=3600, cast_type=int),
    "password_pepper": get_env("PASSWORD_PEPPER", default=""),
}

# ------------------------- AWS CONFIG --------------------------
AWS_CONFIG = {
    "access_key_id": get_env("AWS_ACCESS_KEY_ID", required=False),
    "secret_access_key": get_env("AWS_SECRET_ACCESS_KEY", required=False),
    "region": get_env("AWS_REGION", default="us-east-1", required=False),
    "s3_backup_bucket": get_env("S3_BACKUP_BUCKET", default="my-default-bucket", required=False)
}

# ------------------------- GENERAL SETTINGS --------------------
GENERAL_SETTINGS = {
    "app_name": get_env("APP_NAME", default="CyberShieldAI"),
    "environment": get_env("ENVIRONMENT", default="development"),  # development / production
    "log_level": get_env("LOG_LEVEL", default="INFO")
}
