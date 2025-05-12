import io
import os
import shutil
import tempfile
import secrets
from django.test import TestCase, Client
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from cryptography.fernet import Fernet, InvalidToken
from hackshield.utils.encryption import (
    generate_file_key, encrypt_bytes, decrypt_bytes,
    encrypt_stream, decrypt_stream, DecryptionError
)

class EncryptionUtilsTest(TestCase):
    def test_encrypt_decrypt_bytes_small(self):
        """Round-trip encrypt_bytes/decrypt_bytes for small payload"""
        original = b"hello world"
        key = Fernet.generate_key()
        token = encrypt_bytes(original, key)
        result = decrypt_bytes(token, key)
        self.assertEqual(result, original)

    def test_encrypt_decrypt_bytes_large(self):
        """Round-trip encrypt_bytes/decrypt_bytes for a large payload"""
        original = secrets.token_bytes(100_000)
        key = Fernet.generate_key()
        token = encrypt_bytes(original, key)
        result = decrypt_bytes(token, key)
        self.assertEqual(result, original)

class EncryptionStreamTest(TestCase):
    def test_encrypt_decrypt_stream(self):
        """Use BytesIO to simulate file encryption and decryption streams"""
        # Prepare large random data spanning multiple chunks
        data = secrets.token_bytes(50_000)
        key = Fernet.generate_key()

        # Encrypt to BytesIO
        in_stream = io.BytesIO(data)
        encrypted_stream = io.BytesIO()
        encrypt_stream(in_stream, encrypted_stream, key)

        # Decrypt back
        encrypted_stream.seek(0)
        out_stream = io.BytesIO()
        decrypt_stream(encrypted_stream, out_stream, key)

        # Verify full recovery
        self.assertEqual(out_stream.getvalue(), data)

    def test_decrypt_stream_with_invalid_token(self):
        """Invalid token in stream should raise DecryptionError"""
        # Craft a bad stream: length header but random bytes
        bad_stream = io.BytesIO()
        bad_stream.write((10).to_bytes(4, 'big') + b"0123456789")
        bad_stream.seek(0)
        with self.assertRaises(DecryptionError):
            decrypt_stream(bad_stream, io.BytesIO(), Fernet.generate_key())

class EncryptionIntegrationTest(TestCase):
    def setUp(self):
        # Create a temporary directory and override media paths
        self.tmpdir = tempfile.mkdtemp()
        for attr in ('ENCRYPTED_DIR', 'DECRYPTED_DIR', 'UPLOADS_DIR', 'KEYS_DIR'):
            setattr(settings, attr, self.tmpdir)
        os.makedirs(self.tmpdir, exist_ok=True)
        self.client = Client()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_encrypt_and_decrypt_file_endpoints(self):
        """Integration: encrypt endpoint followed by decrypt returns original file"""
        # Original file content
        content = b"Integration test content for endpoints"
        upload = SimpleUploadedFile('test.txt', content, content_type='text/plain')

        # Call encrypt endpoint
        resp_enc = self.client.post('/encrypt/', {'file': upload})
        self.assertEqual(resp_enc.status_code, 200)
        data_enc = resp_enc.json()
        self.assertEqual(data_enc.get('status'), 'success')
        enc_name = data_enc['encrypted_file']
        key_str = data_enc['encryption_key']

        # Verify encrypted file exists
        enc_path = os.path.join(settings.ENCRYPTED_DIR, enc_name)
        self.assertTrue(os.path.exists(enc_path))
        encrypted_bytes = open(enc_path, 'rb').read()

        # Prepare for decrypt
        encrypted_upload = SimpleUploadedFile(enc_name, encrypted_bytes)
        resp_dec = self.client.post(
            '/decrypt/',
            {'encrypted_file': encrypted_upload, 'encryption_key': key_str}
        )
        self.assertEqual(resp_dec.status_code, 200)
        data_dec = resp_dec.json()
        self.assertEqual(data_dec.get('status'), 'success')
        dec_name = data_dec['decrypted_file']

        # Verify decrypted content matches original
        dec_path = os.path.join(settings.DECRYPTED_DIR, dec_name)
        self.assertTrue(os.path.exists(dec_path))
        decrypted_bytes = open(dec_path, 'rb').read()
        self.assertEqual(decrypted_bytes, content)
