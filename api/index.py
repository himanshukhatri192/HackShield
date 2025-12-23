import os
import sys

# Ensure project root is on the path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hackshield.settings")

from hackshield.wsgi import application  # noqa: E402

# Vercel expects a callable named "app"
app = application

