from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
from cryptography.fernet import Fernet
import os
import hashlib
from scapy.all import sniff
import pandas as pd


def home(request):
	return render(request, "index.html")
def detect_anomaly(request):
    packets = sniff(count=100)  # Capture 100 packets
    df = pd.DataFrame([{"src": pkt.src, "dst": pkt.dst, "len": len(pkt)} for pkt in packets])

    threshold = df["len"].mean() * 2
    anomalies = df[df["len"] > threshold]

    # Save Report
    report = Report(file_name="Network Traffic", report_type="Anomaly Detection",
                    details=f"{len(anomalies)} Anomalies Detected" if not anomalies.empty else "No Anomalies")

    report.save()

    return render(request, 'network.html', {"result": f"{len(anomalies)} Anomalies Detected" if not anomalies.empty else "No Anomalies" })


MALWARE_SIGNATURES = [
    "098f6bcd4621d373cade4e832627b4f6",  # Example MD5 hash of malware
]

def analyze(request):
    if request.method == "POST" and request.FILES['file']:
        uploaded_file = request.FILES['file']
        fs = FileSystemStorage()
        file_path = fs.save(uploaded_file.name, uploaded_file)

        # Calculate file hash
        hasher = hashlib.md5()
        with open(fs.path(file_path), "rb") as f:
            hasher.update(f.read())

        file_hash = hasher.hexdigest()
        is_malware = file_hash in MALWARE_SIGNATURES

        # Save Report
        report = Report(file_name=uploaded_file.name, report_type="Malware Analysis",
                        details="Malicious" if is_malware else "Safe")
        report.save()

        return render(request, 'analyze.html', {"result": "Malware Detected!" if is_malware else "File is Safe"})

    return render(request, 'analyze.html')


# Encryption Key Storage
KEY_FILE = "encryption_key.key"

def generate_key():
    """Generates & stores a key"""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def load_key():
    """Loads an existing key or generates a new one"""
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    return generate_key()

def encrypt_file(request):
    if request.method == "POST" and request.FILES['file']:
        uploaded_file = request.FILES['file']
        fs = FileSystemStorage()
        file_path = fs.save(uploaded_file.name, uploaded_file)

        key = load_key()
        fernet = Fernet(key)

        # Read and encrypt file
        with open(fs.path(file_path), "rb") as file:
            encrypted_data = fernet.encrypt(file.read())

        encrypted_file_path = fs.path("encrypted_" + uploaded_file.name)
        with open(encrypted_file_path, "wb") as enc_file:
            enc_file.write(encrypted_data)

        return render(request, 'encrypt.html', {"encrypted_file": "encrypted_" + uploaded_file.name, "key": key.decode()})
    
    return render(request, 'encrypt.html')

def decrypt_file(request):
    if request.method == "POST":
        file_path = request.POST["file_path"]
        key = request.POST["key"].encode()

        try:
            fernet = Fernet(key)
            fs = FileSystemStorage()
            encrypted_file_path = fs.path(file_path)

            # Read and decrypt file
            with open(encrypted_file_path, "rb") as enc_file:
                decrypted_data = fernet.decrypt(enc_file.read())

            decrypted_file_path = fs.path("decrypted_" + file_path)
            with open(decrypted_file_path, "wb") as dec_file:
                dec_file.write(decrypted_data)

            return render(request, 'decrypt.html', {"decrypted_file": "decrypted_" + file_path})
        
        except Exception as e:
            return render(request, 'decrypt.html', {"error": "Invalid Key or File!"})

    return render(request, 'decrypt.html')

def view_reports(request):
    reports = Report.objects.all()
    return render(request, 'reports.html', {"reports": reports})

def clear_reports(request):
    Report.objects.all().delete()
    return redirect('view_reports')

