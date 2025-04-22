from celery import shared_task
from django.conf import settings
from django.core.files.storage import default_storage
import os
import hashlib
import mimetypes

from .utils.encryption import (
    generate_file_key,
    load_file_key,
    encrypt_stream,
    decrypt_bytes,
    DecryptionError,
)
from .models import ScanHistory, Report, MalwareSignature


@shared_task(bind=True)
def encrypt_task(self, file_name):
    """
    Celery task to encrypt a file stored in the uploads directory.
    """
    uploads_dir = settings.UPLOADS_DIR
    encrypted_dir = settings.ENCRYPTED_DIR
    key_dir = settings.KEYS_DIR

    # Paths
    in_path = os.path.join(uploads_dir, file_name)
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"Input file not found: {in_path}")

    # Generate and store key for this file
    key = generate_file_key(file_name)

    # Prepare output path
    encrypted_name = f"{file_name}.enc"
    out_path = os.path.join(encrypted_dir, encrypted_name)

    # Encrypt stream
    with open(in_path, 'rb') as in_stream, open(out_path, 'wb') as out_stream:
        encrypt_stream(in_stream, out_stream, key)

    # Record status
    ScanHistory.objects.create(
        file_name=file_name,
        result='encrypted'
    )
    return {'status': 'success', 'encrypted_file': encrypted_name}


@shared_task(bind=True)
def decrypt_task(self, encrypted_file_name):
    """
    Celery task to decrypt a file stored in the encrypted directory.
    """
    encrypted_dir = settings.ENCRYPTED_DIR
    decrypted_dir = settings.DECRYPTED_DIR

    in_path = os.path.join(encrypted_dir, encrypted_file_name)
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"Encrypted file not found: {in_path}")

    # Derive original file name (strip .enc)
    base_name, ext = os.path.splitext(encrypted_file_name)
    key_name = base_name

    # Load the key
    try:
        key = load_file_key(key_name)
    except FileNotFoundError as e:
        raise

    # Read encrypted data and decrypt
    with open(in_path, 'rb') as in_stream:
        token = in_stream.read()
    try:
        data = decrypt_bytes(token, key)
    except DecryptionError as e:
        raise

    # Write decrypted output
    out_path = os.path.join(decrypted_dir, base_name)
    with open(out_path, 'wb') as out_stream:
        out_stream.write(data)

    # Record status
    ScanHistory.objects.create(
        file_name=encrypted_file_name,
        result='decrypted'
    )
    return {'status': 'success', 'decrypted_file': base_name}


@shared_task(bind=True)
def scan_task(self, file_name):
    """
    Celery task to scan a file stored in the uploads directory against known malware signatures.
    """
    uploads_dir = settings.UPLOADS_DIR
    in_path = os.path.join(uploads_dir, file_name)
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"File to scan not found: {in_path}")

    # Read file and compute hash
    with open(in_path, 'rb') as f:
        content = f.read()
    file_hash = hashlib.sha256(content).hexdigest()

    # Check for matching malware signatures
    signature = MalwareSignature.objects.filter(signature_hash=file_hash).first()

    if signature:
        malware_detected = 'Yes'
        threat_level = 'High'
        threat_name = signature.name
        recommendations = signature.description or 'Remove or quarantine the file.'
    else:
        malware_detected = 'No'
        threat_level = 'None'
        threat_name = ''
        recommendations = 'No action required.'

    # File metadata
    file_size = f"{os.path.getsize(in_path)} bytes"
    mime_type, _ = mimetypes.guess_type(in_path)
    file_type = mime_type or 'unknown'

    # Create scan report
    report = Report.objects.create(
        file_name=file_name,
        malware_detected=malware_detected,
        threat_level=threat_level,
        threat_name=threat_name,
        recommendations=recommendations,
        file_size=file_size,
        file_type=file_type,
        file_hash=file_hash
    )

    # Record scan history
    ScanHistory.objects.create(
        file_name=file_name,
        result=f"scanned: {malware_detected}"
    )

    return {
        'status': 'success',
        'report_id': report.id,
        'malware_detected': malware_detected
    }
