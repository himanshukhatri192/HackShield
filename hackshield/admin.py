from django.contrib import admin
from .models import Report, MalwareSignature, ScanHistory

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'threat_level', 'malware_detected', 'scan_date')
    list_filter = ('threat_level', 'malware_detected', 'scan_date')
    search_fields = ('file_name', 'threat_name')

@admin.register(MalwareSignature)
class MalwareSignatureAdmin(admin.ModelAdmin):
    list_display = ('name', 'signature_hash', 'created_at')
    search_fields = ('name', 'signature_hash')
    list_filter = ('created_at',)

@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'scan_date', 'result')
    search_fields = ('file_name',)
    list_filter = ('scan_date', 'result')
