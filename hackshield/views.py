import os
import hashlib
import datetime
from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse, FileResponse
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken
from .utils.encryption import (
    generate_file_key, load_file_key, encrypt_bytes, decrypt_bytes,
    encrypt_stream, decrypt_stream, DecryptionError
)
import pandas as pd
from scapy.all import sniff, conf
from .models import Report
import base64
import secrets
import logging


# Directory Paths Configuration
ENCRYPTED_DIR = getattr(settings, 'ENCRYPTED_DIR', 'media/encrypted/')
DECRYPTED_DIR = getattr(settings, 'DECRYPTED_DIR', 'media/decrypted/')
KEYS_DIR = getattr(settings, 'KEYS_DIR', 'media/keys/')
UPLOADS_DIR = getattr(settings, 'UPLOADS_DIR', 'media/uploads/')

# Ensure required directories exist
for directory in [ENCRYPTED_DIR, DECRYPTED_DIR, KEYS_DIR, UPLOADS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Security Configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MALWARE_SIGNATURES = {
    "d41d8cd98f00b204e9800998ecf8427e": "Empty file",
    "5d41402abc4b2a76b9719d911017c592": "Test malware signature"
}
SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.bat', '.ps1', '.sh', '.js', '.vbs']

def home(request):
    """Home page view"""
    return render(request, "index.html")

def detect_anomaly(request):
    """Network anomaly detection view"""
    conf.L3socket = conf.L3socket6
    
    try:
        # Capture network packets
        packets = sniff(count=100, timeout=30)
        data = []

        for pkt in packets:
            if hasattr(pkt, "src") and hasattr(pkt, "dst"):
                data.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": pkt.src,
                    "destination_ip": pkt.dst,
                    "length": len(pkt),
                    "protocol": pkt.name
                })

        df = pd.DataFrame(data)

        # Detect anomalies
        threshold = df["length"].mean() * 2 if not df.empty else 0
        anomalies = df[df["length"] > threshold]

        report_status = "Network is SAFE" if anomalies.empty else f"⚠ {len(anomalies)} Anomalies Detected!"

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                "status": report_status,
                "anomalies": anomalies.to_dict(orient="records")
            })

        return render(request, "network.html", {
            "anomalies": anomalies.to_dict(orient="records"),
            "result": report_status
        })

    except Exception as e:
        error_msg = f"Error: {str(e)}"
        return JsonResponse({"status": error_msg}, status=500)

def analyze(request):
    """File analysis view"""
    if request.method == 'POST':
        if not request.FILES.get('file'):
            error_msg = 'No file selected'
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'status': 'error', 'message': error_msg}, status=400)
            return render(request, 'analyze.html', {'error': error_msg})

        uploaded_file = request.FILES['file']
        fs = FileSystemStorage(location=UPLOADS_DIR)
        file_path = None
        
        try:
            # Validate file
            if uploaded_file.size > MAX_FILE_SIZE:
                raise ValueError("File size exceeds maximum limit of 100MB")

            if not uploaded_file.name:
                raise ValueError("Invalid file name")

            # Save file temporarily
            file_path = fs.save(uploaded_file.name, uploaded_file)
            full_path = fs.path(file_path)

            # Scan the file
            scan_results = scan_file(full_path)
            
            # Prepare analysis results
            analysis_result = {
                'filename': uploaded_file.name,
                'file_size': f"{uploaded_file.size/1024:.2f} KB",
                'file_type': uploaded_file.content_type,
                'malware': "Yes" if scan_results['malware_found'] else "No",
                'threat_level': scan_results['threat_level'],
                'threat_name': scan_results['threat_name'],
                'recommendations': scan_results['recommendations'],
                'security_score': 0 if scan_results['malware_found'] else 100,
                'file_hash': scan_results['file_hash'],
                'scan_date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'status': 'success'
            }

            # Save to database
            Report.objects.create(
                file_name=uploaded_file.name,
                malware_detected=analysis_result['malware'],
                threat_level=scan_results['threat_level'],
                threat_name=scan_results['threat_name'],
                recommendations=scan_results['recommendations'],
                file_size=analysis_result['file_size'],
                file_type=uploaded_file.content_type,
                file_hash=scan_results['file_hash']
            )

            # Return response
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'complete',
                    'result': analysis_result,
                    'report_url': '/analyze/'
                })
            
            return render(request, 'analyze.html', {'analysis_result': analysis_result})

        except Exception as e:
            error_message = str(e)
            if file_path and fs.exists(file_path):
                fs.delete(file_path)
                
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'error',
                    'message': error_message
                }, status=500)
            
            return render(request, 'analyze.html', {'error': error_message})
    
    return render(request, 'analyze.html')

def delete_file(request):
    if request.method == 'POST':
        file_path = request.POST.get('file_path')
        
        # Security checks
        if not validate_file_path(file_path):  # Implement proper validation
            return JsonResponse({'status': 'error', 'message': 'Invalid file path'})
            
        try:
            os.remove(file_path)
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})


def scan_file(file_path):
    """Enhanced file scanning with multiple detection methods"""
    try:
        # Verify file exists and is readable
        if not os.path.exists(file_path):
            raise FileNotFoundError("File not found after upload")
        
        if not os.access(file_path, os.R_OK):
            raise PermissionError("Cannot read uploaded file")

        # Calculate file hash
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        # Check against known signatures
        if file_hash in MALWARE_SIGNATURES:
            return {
                'malware_found': True,
                'threat_level': "Critical",
                'threat_name': MALWARE_SIGNATURES[file_hash],
                'recommendations': "Known malware signature detected. Delete this file immediately.",
                'file_hash': file_hash
            }

        # Check file extension
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in SUSPICIOUS_EXTENSIONS:
            return {
                'malware_found': True,
                'threat_level': "High",
                'threat_name': f"Suspicious file type ({file_ext})",
                'recommendations': f"Executable file type detected ({file_ext}). Use with caution.",
                'file_hash': file_hash
            }

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > 50 * 1024 * 1024:  # 50MB
            return {
                'malware_found': True,
                'threat_level': "Medium",
                'threat_name': "Oversized file",
                'recommendations': "Large file size may indicate potential threat",
                'file_hash': file_hash
            }

        # If all checks pass
        return {
            'malware_found': False,
            'threat_level': "Low",
            'threat_name': "No known threats",
            'recommendations': "File appears safe",
            'file_hash': file_hash
        }

    except Exception as e:
        raise Exception(f"Scanning error: {str(e)}")

# Configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
SALT_SIZE = 16  # 128-bit salt
ITERATIONS = 390000  # OWASP recommended iterations for PBKDF2-HMAC-SHA256

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def encrypt_file(request):
    """Handle file encryption"""
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]
        
        try:
            # Validate file size
            if uploaded_file.size > MAX_FILE_SIZE:
                raise ValueError("File size exceeds maximum limit of 100MB")

            # Generate and store encryption key
            key = generate_file_key(uploaded_file.name)
            
            # Save encrypted file using streaming encryption
            encrypted_filename = f"encrypted_{uploaded_file.name}"
            encrypted_path = os.path.join(settings.ENCRYPTED_DIR, encrypted_filename)
            
            with open(encrypted_path, "wb") as enc_file:
                encrypt_stream(uploaded_file, enc_file, key)

            logger.info(f"File encrypted successfully: {uploaded_file.name}")

            return JsonResponse({
                "status": "success",
                "message": "File encrypted successfully!",
                "encrypted_file": encrypted_filename,
                "download_url": f"/download_encrypted/{encrypted_filename}",
                "encryption_key": key.decode()  # Send key to user (in real app, use secure channel)
            })

        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            return JsonResponse({
                "status": "error",
                "message": f"Encryption failed: {str(e)}"
            }, status=500)

    return render(request, "encrypt.html")

def decrypt_file(request):
    """Handle file decryption"""
    if request.method == "POST":
        encrypted_file = request.FILES.get("encrypted_file")
        encryption_key = request.POST.get("encryption_key")

        if not encrypted_file:
            return JsonResponse({
                "status": "error",
                "message": "No file provided"
            }, status=400)

        # Get original filename for key lookup if needed
        original_filename = encrypted_file.name.replace('encrypted_', '')
        decrypted_filename = f"decrypted_{original_filename}"
        decrypted_path = os.path.join(settings.DECRYPTED_DIR, decrypted_filename)
        
        # Get key from POST or load from file
        key_bytes = None
        try:
            if encryption_key:
                key_bytes = encryption_key.encode()
            else:
                # Try to load key from storage if not provided
                try:
                    key_bytes = load_file_key(original_filename)
                    logger.info(f"Using stored key for {original_filename}")
                except FileNotFoundError:
                    return JsonResponse({
                        "status": "error",
                        "message": "Encryption key is required and no stored key was found"
                    }, status=400)
            
            # Decrypt file using streaming decryption
            with open(decrypted_path, "wb") as dec_file:
                decrypt_stream(encrypted_file, dec_file, key_bytes)

            logger.info(f"File decrypted successfully: {original_filename}")

            return JsonResponse({
                "status": "success",
                "message": "File decrypted successfully!",
                "decrypted_file": decrypted_filename,
                "download_url": f"/download_decrypted/{decrypted_filename}",
                "original_filename": original_filename
            })

        except DecryptionError as e:
            logger.warning(f"Decryption failed - {str(e)}")
            
            # Fallback to legacy decryption if streaming fails
            try:
                logger.info("Attempting fallback to non-streaming decryption")
                # Reset file pointer
                encrypted_file.seek(0)
                
                # Read entire file
                encrypted_content = b''
                for chunk in encrypted_file.chunks():
                    encrypted_content += chunk
                
                # Decrypt using non-streaming method
                decrypted_data = decrypt_bytes(encrypted_content, key_bytes)
                
                # Save decrypted file
                with open(decrypted_path, "wb") as dec_file:
                    dec_file.write(decrypted_data)
                
                logger.info(f"File decrypted successfully using fallback method: {original_filename}")
                
                return JsonResponse({
                    "status": "success",
                    "message": "File decrypted successfully (using legacy method)!",
                    "decrypted_file": decrypted_filename,
                    "download_url": f"/download_decrypted/{decrypted_filename}",
                    "original_filename": original_filename
                })
                
            except (InvalidToken, DecryptionError):
                logger.warning("Decryption failed - invalid encryption key")
                return JsonResponse({
                    "status": "error",
                    "message": "Decryption failed - invalid encryption key or corrupted file"
                }, status=400)
                
        except InvalidToken:
            logger.warning("Decryption failed - invalid encryption key")
            return JsonResponse({
                "status": "error",
                "message": "Decryption failed - invalid encryption key"
            }, status=400)
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return JsonResponse({
                "status": "error",
                "message": f"Decryption failed: {str(e)}"
            }, status=400)

    return render(request, "decrypt.html")

def download_encrypted(request, filename):
    """Serve encrypted file for download"""
    file_path = os.path.join(settings.ENCRYPTED_DIR, filename)
    if os.path.exists(file_path):
        response = FileResponse(open(file_path, 'rb'), as_attachment=True)
        response['Content-Length'] = os.path.getsize(file_path)
        return response
    return JsonResponse({"error": "File not found"}, status=404)

def download_decrypted(request, filename):
    """Serve decrypted file for download"""
    file_path = os.path.join(settings.DECRYPTED_DIR, filename)
    if os.path.exists(file_path):
        response = FileResponse(open(file_path, 'rb'), as_attachment=True)
        response['Content-Length'] = os.path.getsize(file_path)
        
        # Optional: Delete after download for security
        # os.remove(file_path)
        
        return response
    return JsonResponse({"error": "File not found"}, status=404)
def view_reports(request):
    """View all scan reports"""
    reports = Report.objects.all().order_by('-scan_date')
    return render(request, "reports.html", {"reports": reports})

def clear_reports(request):
    """Clear all reports"""
    Report.objects.all().delete()
    return redirect("view_reports")
