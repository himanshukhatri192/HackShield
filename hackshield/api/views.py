from django.conf import settings
from django.urls import reverse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from celery.result import AsyncResult
import os

from .serializers import FileSerializer, TaskStatusSerializer
from hackshield.tasks import encrypt_task, decrypt_task


class EncryptAPIView(APIView):
    """
    API endpoint to upload a file and start encryption as a Celery task.
    """
    def post(self, request, *args, **kwargs):
        serializer = FileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        upload = serializer.validated_data['file']
        # Save uploaded file to uploads directory
        upload_path = os.path.join(settings.UPLOADS_DIR, upload.name)
        with open(upload_path, 'wb+') as dest:
            for chunk in upload.chunks():
                dest.write(chunk)

        # Dispatch encryption task
        task = encrypt_task.delay(upload.name)
        return Response({'task_id': task.id}, status=status.HTTP_202_ACCEPTED)


class DecryptAPIView(APIView):
    """
    API endpoint to upload an encrypted file and start decryption as a Celery task.
    """
    def post(self, request, *args, **kwargs):
        serializer = FileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        upload = serializer.validated_data['file']
        # Save uploaded file to encrypted directory
        enc_path = os.path.join(settings.ENCRYPTED_DIR, upload.name)
        with open(enc_path, 'wb+') as dest:
            for chunk in upload.chunks():
                dest.write(chunk)

        # Dispatch decryption task
        task = decrypt_task.delay(upload.name)
        return Response({'task_id': task.id}, status=status.HTTP_202_ACCEPTED)


class TaskStatusAPIView(APIView):
    """
    API endpoint to poll the status of a Celery task.
    """
    def get(self, request, *args, **kwargs):
        task_id = request.query_params.get('task_id')
        if not task_id:
            return Response({'detail': 'task_id query parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)

        result = AsyncResult(task_id)
        state = result.status
        # Determine progress: 0 for pending, 100 for success, else unknown
        if state == 'SUCCESS':
            progress = 100
        elif state in ('PENDING', 'RECEIVED', 'STARTED'):
            progress = 0
        else:
            progress = 0

        # Build result URL if available
        result_url = None
        if state == 'SUCCESS' and result.result:
            res = result.result
            # Encryption result
            enc_file = res.get('encrypted_file')
            if enc_file:
                url = reverse('download_encrypted', kwargs={'filename': enc_file})
                result_url = request.build_absolute_uri(url)
            # Decryption result
            dec_file = res.get('decrypted_file')
            if dec_file:
                url = reverse('download_decrypted', kwargs={'filename': dec_file})
                result_url = request.build_absolute_uri(url)

        data = {
            'task_id': task_id,
            'status': state,
            'progress': progress,
            'result_url': result_url
        }
        serializer = TaskStatusSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)
