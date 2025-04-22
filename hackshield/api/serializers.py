from rest_framework import serializers


class FileSerializer(serializers.Serializer):
    """
    Serializer for handling file uploads.
    """
    file = serializers.FileField()


class TaskStatusSerializer(serializers.Serializer):
    """
    Serializer for reporting asynchronous task status, progress, and result location.
    """
    task_id = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    progress = serializers.IntegerField(read_only=True)
    result_url = serializers.URLField(read_only=True)
