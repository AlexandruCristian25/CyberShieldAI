import os
import boto3
import logging
import hashlib
from botocore.exceptions import ClientError
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("backup")
logger.setLevel(logging.INFO)

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_DEFAULT_BUCKET = os.getenv("S3_BACKUP_BUCKET", "my-backup-bucket")

def calculate_md5(file_path: str) -> str:
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def upload_backup_to_s3(file_path: str, s3_bucket: Optional[str] = None, s3_prefix: Optional[str] = None) -> bool:
    if not os.path.exists(file_path):
        logger.error(f"[Eroare] Fișierul nu există: {file_path}")
        return False

    s3_bucket = s3_bucket or S3_DEFAULT_BUCKET
    s3_prefix = s3_prefix or datetime.utcnow().strftime("backups/%Y-%m-%d/")
    s3_key = os.path.join(s3_prefix, os.path.basename(file_path))

    try:
        session = boto3.session.Session()
        if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
            s3 = session.client(
                "s3",
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                region_name=AWS_REGION,
                config=boto3.session.Config(
                    retries={'max_attempts': 5, 'mode': 'adaptive'},
                    connect_timeout=10,
                    read_timeout=30
                )
            )
        else:
            # Use IAM role if credentials are not explicitly set
            s3 = session.client(
                "s3",
                region_name=AWS_REGION,
                config=boto3.session.Config(
                    retries={'max_attempts': 5, 'mode': 'adaptive'},
                    connect_timeout=10,
                    read_timeout=30
                )
            )

        md5_local = calculate_md5(file_path)

        s3.upload_file(
            Filename=file_path,
            Bucket=s3_bucket,
            Key=s3_key,
            ExtraArgs={
                'ServerSideEncryption': 'AES256',
                'Tagging': f"BackupDate={datetime.utcnow().isoformat()},Source=CyberShieldAI"
            }
        )
        logger.info(f"[OK] Backup încărcat: s3://{s3_bucket}/{s3_key}")

        # Verificare integritate cu ETag
        head = s3.head_object(Bucket=s3_bucket, Key=s3_key)
        etag = head['ETag'].strip('"')
        if etag != md5_local:
            logger.error(f"[Eroare] Checksum mismatch pentru {file_path}")
            return False

        return True

    except ClientError as e:
        logger.error(f"[Eroare AWS] {e.response.get('Error', {}).get('Message', str(e))}")
    except Exception as e:
        logger.error(f"[Eroare necunoscută] {str(e)}")

    return False
