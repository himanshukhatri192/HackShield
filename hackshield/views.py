import os
import hashlib
import datetime
from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse, FileResponse
from django.conf import settings
from cryptography.fernet import Fernet
import pandas as pd
from scapy.all import sniff, conf
from .models import Report

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

def generate_key():
    """Generate a new Fernet key"""
    return Fernet.generate_key()

def load_key(filename):
    """Load or generate a key for a specific file"""
    key_path = os.path.join(KEYS_DIR, f"{filename}.key")
    
    if os.path.exists(key_path):
        with open(key_path, "rb") as key_file:
            return key_file.read()
    
    key = generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    return key

def encrypt_file(request):
    """File encryption view"""
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]
        
        try:
            # Validate file size
            if uploaded_file.size > MAX_FILE_SIZE:
                raise ValueError("File size exceeds maximum limit of 100MB")

            # Save original file temporarily
            fs = FileSystemStorage(location=ENCRYPTED_DIR)
            file_path = fs.save(uploaded_file.name, uploaded_file)
            full_path = os.path.join(ENCRYPTED_DIR, file_path)

            # Get or generate key
            key = load_key(uploaded_file.name)
            fernet = Fernet(key)

            # Encrypt file
            with open(full_path, "rb") as file:
                encrypted_data = fernet.encrypt(file.read())

            # Save encrypted file
            encrypted_filename = f"encrypted_{uploaded_file.name}"
            encrypted_path = os.path.join(ENCRYPTED_DIR, encrypted_filename)
            
            with open(encrypted_path, "wb") as enc_file:
                enc_file.write(encrypted_data)

            # Clean up
            os.remove(full_path)

            return JsonResponse({
                "status": "success",
                "message": "File encrypted successfully!",
                "encrypted_file": encrypted_filename,
                "download_url": f"/download_encrypted/{encrypted_filename}",
                "key": key.decode()  # Note: In production, don't return the key!
            })

        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": str(e)
            }, status=500)

    return render(request, "encrypt.html")

def decrypt_file(request):
    """File decryption view"""
    if request.method == "POST":
        encrypted_file = request.FILES.get("encrypted_file")
        user_key = request.POST.get("key")

        if not encrypted_file:
            return JsonResponse({
                "status": "error",
                "message": "No file provided"
            }, status=400)

        if not user_key:
            return JsonResponse({
                "status": "error",
                "message": "Encryption key is required"
            }, status=400)

        try:
            # Save encrypted file temporarily
            fs = FileSystemStorage(location=DECRYPTED_DIR)
            file_path = fs.save(f"temp_{encrypted_file.name}", encrypted_file)
            full_path = os.path.join(DECRYPTED_DIR, file_path)

            # Decrypt file
            fernet = Fernet(user_key.encode())
            
            with open(full_path, "rb") as file:
                decrypted_data = fernet.decrypt(file.read())

            # Save decrypted file
            decrypted_filename = f"decrypted_{encrypted_file.name.replace('encrypted_', '')}"
            decrypted_path = os.path.join(DECRYPTED_DIR, decrypted_filename)
            
            with open(decrypted_path, "wb") as dec_file:
                dec_file.write(decrypted_data)

            # Clean up
            os.remove(full_path)

            return JsonResponse({
                "status": "success",
                "message": "File decrypted successfully!",
                "decrypted_file": decrypted_filename,
                "download_url": f"/download_decrypted/{decrypted_filename}"
            })

        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": f"Decryption failed: {str(e)}"
            }, status=400)

    return render(request, "decrypt.html")

def download_encrypted(request, filename):
    """Serve encrypted file for download"""
    file_path = os.path.join(ENCRYPTED_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'), as_attachment=True)
    return JsonResponse({"error": "File not found"}, status=404)

def download_decrypted(request, filename):
    """Serve decrypted file for download"""
    file_path = os.path.join(DECRYPTED_DIR, filename)
    if os.path.exists(file_path):
        response = FileResponse(open(file_path, 'rb'), as_attachment=True)
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