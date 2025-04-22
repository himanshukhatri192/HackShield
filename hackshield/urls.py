from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('analyze/', views.analyze, name='analyze'),
    path('network/', views.detect_anomaly, name='network'),
    path('encrypt/', views.encrypt_file, name='encrypt_file'),
    path('decrypt/', views.decrypt_file, name='decrypt_file'),
    path('reports/', views.view_reports, name='view_reports'),
    path('clear-reports/', views.clear_reports, name='clear_reports'),
    path('download_encrypted/<str:filename>/', views.download_encrypted, name='download_encrypted'),
    path('download_decrypted/<str:filename>/', views.download_decrypted, name='download_decrypted'),
    path('accounts/', include('accounts.urls')),
    path('api/', include('hackshield.api.urls')),
]
