"""WS-01·06 위험한 설정을 심은 Django settings. expect 주석 다음 줄에서 그 규칙이 잡혀야 한다."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# expect: config-weak-secret
SECRET_KEY = "django-insecure-change-me-before-deploying-this-app"
# expect: config-debug
DEBUG = True
# expect: config-allowed-hosts
ALLOWED_HOSTS = ["*"]
# expect: config-cookie-flags
SESSION_COOKIE_SECURE = False

# expect: secret-hardcoded
STRIPE_API_KEY = "{{FAKE:stripe}}"

INSTALLED_APPS = ["django.contrib.admin", "django.contrib.auth", "rest_framework", "shop"]
ROOT_URLCONF = "mysite.urls"
