from django.db import models

class Report(models.Model):
    file_name = models.CharField(max_length=255)
    report_type = models.CharField(max_length=100)  # Malware or Anomaly
    details = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file_name} - {self.report_type}"
