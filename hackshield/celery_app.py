import os
from celery import Celery

# Set default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hackshield.settings')

app = Celery('hackshield')

# Load task modules from all registered Django app configs.
# Broker and backend URLs are read from settings with the CELERY_ namespace.
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    """
    Optional debug task to verify Celery is configured correctly.
    """
    print(f'Request: {self.request!r}')
