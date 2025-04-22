import os
import hashlib
import datetime
from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse, FileResponse
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken
from .utils.encryption import generate_file_key, load_file_key, encrypt_bytes, decrypt_bytes
from .tasks import encrypt_task, decrypt_task
from celery.result import AsyncResult
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
    """Handle file encryption using Celery task"""
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]
        
        try:
            # Validate file size
            if uploaded_file.size > MAX_FILE_SIZE:
                raise ValueError("File size exceeds maximum limit of 100MB")

            # Save file to uploads directory
            fs = FileSystemStorage(location=UPLOADS_DIR)
            file_name = fs.save(uploaded_file.name, uploaded_file)
            
            # Dispatch Celery task
            task = encrypt_task.delay(file_name)
            
            logger.info(f"Encryption task dispatched for: {file_name}, task_id: {task.id}")

            return JsonResponse({
                "status": "pending",
                "message": "File encryption started",
                "task_id": task.id,
                "file_name": file_name
            })

        except Exception as e:
            logger.error(f"Encryption task dispatch failed: {str(e)}")
            return JsonResponse({
                "status": "error",
                "message": f"Encryption failed: {str(e)}"
            }, status=500)

    return render(request, "encrypt.html")

def decrypt_file(request):
    """Handle file decryption using Celery task"""
    if request.method == "POST":
        encrypted_file = request.FILES.get("encrypted_file")

        if not encrypted_file:
            return JsonResponse({
                "status": "error",
                "message": "No file provided"
            }, status=400)

        try:
            # Save encrypted file to encrypted directory
            fs = FileSystemStorage(location=ENCRYPTED_DIR)
            file_name = fs.save(encrypted_file.name, encrypted_file)
            
            # Dispatch Celery task
            task = decrypt_task.delay(file_name)
            
            logger.info(f"Decryption task dispatched for: {file_name}, task_id: {task.id}")

            return JsonResponse({
                "status": "pending",
                "message": "File decryption started",
                "task_id": task.id,
                "file_name": file_name
            })

        except Exception as e:
            logger.error(f"Decryption task dispatch failed: {str(e)}")
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

def task_status(request, task_id):
    """Check the status of a Celery task and return results"""
    task_result = AsyncResult(task_id)
    
    if task_result.state == 'PENDING':
        response = {
            'status': 'pending',
            'message': 'Task is still processing'
        }
    elif task_result.state == 'SUCCESS':
        result = task_result.result
        response = {
            'status': 'success',
            'message': 'Task completed successfully',
            'result': result
        }
        
        # Add download URL if available
        if 'encrypted_file' in result:
            response['download_url'] = f"/download_encrypted/{result['encrypted_file']}"
        elif 'decrypted_file' in result:
            response['download_url'] = f"/download_decrypted/{result['decrypted_file']}"
    elif task_result.state == 'FAILURE':
        response = {
            'status': 'error',
            'message': f'Task failed: {str(task_result.result)}'
        }
    else:
        response = {
            'status': task_result.state.lower(),
            'message': f'Task is in {task_result.state} state'
        }
    
    return JsonResponse(response)

def view_reports(request):
    """View all scan reports"""
    reports = Report.objects.all().order_by('-scan_date')
    return render(request, "reports.html", {"reports": reports})

def clear_reports(request):
    """Clear all reports"""
    Report.objects.all().delete()
    return redirect("view_reports")
