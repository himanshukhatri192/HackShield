from django.urls import path

from .views import EncryptAPIView, DecryptAPIView, TaskStatusAPIView

urlpatterns = [
    path('encrypt/', EncryptAPIView.as_view(), name='encrypt'),
    path('decrypt/', DecryptAPIView.as_view(), name='decrypt'),
    path('status/<str:task_id>/', TaskStatusAPIView.as_view(), name='status'),
]
