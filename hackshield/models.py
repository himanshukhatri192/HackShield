from django.db import models

class Report(models.Model):
    file_name = models.CharField(max_length=255)
    malware_detected = models.CharField(max_length=10)
    threat_level = models.CharField(max_length=20)
    threat_name = models.CharField(max_length=255)
    recommendations = models.TextField()
    file_size = models.CharField(max_length=50)
    file_type = models.CharField(max_length=100)
    file_hash = models.CharField(max_length=64)
    scan_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file_name} - {self.threat_level}"

class MalwareSignature(models.Model):
    name = models.CharField(max_length=255)
    signature_hash = models.CharField(max_length=64, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class ScanHistory(models.Model):
    file_name = models.CharField(max_length=255)
    scan_date = models.DateTimeField(auto_now_add=True)
    result = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.file_name} - {self.result}"