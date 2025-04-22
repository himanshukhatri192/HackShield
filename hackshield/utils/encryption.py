"""
Utility module for handling file encryption and decryption using Fernet.
"""
import os
import hashlib
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken


class DecryptionError(Exception):
    """Raised when decryption fails due to invalid or corrupted token."""
    pass


# Determine keys directory from settings or default
KEYS_DIR = getattr(settings, 'KEYS_DIR', 'media/keys/')

# Ensure the keys directory exists
os.makedirs(KEYS_DIR, exist_ok=True)


def generate_file_key(filename):
    """
    Generate a unique Fernet key for the given filename and store it under KEYS_DIR.
    Returns the generated key (bytes).
    """
    key = Fernet.generate_key()
    # Use SHA-256 of filename for key filename
    digest = hashlib.sha256(filename.encode('utf-8')).hexdigest()
    key_path = os.path.join(KEYS_DIR, f"{digest}.key")
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
    return key


def load_file_key(filename):
    """
    Load the Fernet key for the given filename from KEYS_DIR.
    Raises FileNotFoundError if the key file does not exist.
    """
    digest = hashlib.sha256(filename.encode('utf-8')).hexdigest()
    key_path = os.path.join(KEYS_DIR, f"{digest}.key")
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Encryption key not found for file: {filename}")
    with open(key_path, 'rb') as key_file:
        return key_file.read()


def encrypt_bytes(data, key):
    """
    Encrypt the given bytes using the provided Fernet key.
    Returns the encrypted token as bytes.
    """
    fernet = Fernet(key)
    return fernet.encrypt(data)


def decrypt_bytes(token, key):
    """
    Decrypt the given token using the provided Fernet key.
    Returns the original bytes, or raises DecryptionError if invalid.
    """
    fernet = Fernet(key)
    try:
        return fernet.decrypt(token)
    except InvalidToken as err:
        raise DecryptionError("Decryption failed. Invalid token or wrong key.") from err


def encrypt_stream(in_stream, out_stream, key, chunk_size=8192):
    """
    Read data from in_stream, encrypt in chunks, and write encrypted tokens to out_stream.
    Note: Each chunk is encrypted independently.
    """
    for chunk in iter(lambda: in_stream.read(chunk_size), b""):
        token = encrypt_bytes(chunk, key)
        # Prepend length for proper decryption
        length = len(token).to_bytes(4, byteorder='big')
        out_stream.write(length + token)


def decrypt_stream(in_stream, out_stream, key, chunk_size=8192):
    """
    Read encrypted tokens from in_stream, decrypt them, and write decrypted data to out_stream.
    Each token is expected to be prefixed with its length (4 bytes, big-endian).
    """
    while True:
        # Read the length prefix (4 bytes)
        length_bytes = in_stream.read(4)
        if not length_bytes or len(length_bytes) < 4:
            break  # End of stream or incomplete length prefix
        
        # Convert length bytes to integer
        token_length = int.from_bytes(length_bytes, byteorder='big')
        
        # Read the token
        token = in_stream.read(token_length)
        if not token or len(token) < token_length:
            raise DecryptionError("Incomplete token in encrypted stream")
        
        # Decrypt the token and write to output stream
        decrypted_chunk = decrypt_bytes(token, key)
        out_stream.write(decrypted_chunk)
