"""vuln_django settings를 안전하게 쓴 판. 발견이 하나도 없어야 한다."""
import os

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = ["shop.example.com"]
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")

INSTALLED_APPS = ["django.contrib.admin", "django.contrib.auth", "rest_framework", "shop"]
ROOT_URLCONF = "mysite.urls"
