"""Django 저장소 전체 설정에 달린 판정: 전역 로그인 미들웨어, DRF 기본 권한, 쿠키 Secure 미설정.

settings가 어느 파일에 어떻게 쓰였는지에 따라 결과가 바뀌므로 작은 프로젝트를 만들어 확인한다 (표본은 tests/fixtures/vuln_django).
"""
import pytest

from wescope.analyzers.config import ConfigAnalyzer
from wescope.analyzers.routes import RoutesAnalyzer
from wescope.collector.context import collect
from wescope.collector.snapshot import Target

URLS = 'from django.urls import path\nfrom . import views\nurlpatterns = [path("comments/", views.add_comment)]\n'
VIEW = ('from django.views.decorators.http import require_POST\nfrom .models import Comment\n\n'
        '@require_POST\ndef add_comment(request):\n    Comment.objects.create(body=request.POST["b"])\n')
DRF_URLS = ('from django.urls import include, path\nfrom rest_framework.routers import DefaultRouter\nfrom . import views\n'
            'router = DefaultRouter()\nrouter.register(r"comments", views.CommentViewSet, basename="c")\n'
            'urlpatterns = [path("api/", include(router.urls))]\n')
DRF_VIEW = ('from rest_framework import viewsets\nfrom rest_framework.decorators import action\nfrom .models import Comment\n\n'
            'class CommentViewSet(viewsets.GenericViewSet):\n    @action(detail=False, methods=["post"])\n'
            '    def bulk(self, request):\n        Comment.objects.bulk_create([Comment(body=b) for b in request.data])\n')
LOGIN = "django.contrib.auth.middleware.LoginRequiredMiddleware"


def run(tmp_path, analyzer, files):
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    with collect(Target("folder", str(tmp_path))) as ctx:
        return analyzer.run(ctx).hits


@pytest.mark.parametrize("settings, guarded", [
    (f'MIDDLEWARE = ["{LOGIN}"]\n', True),
    (f'MIDDLEWARE = []\nMIDDLEWARE += ["{LOGIN}"]\n', True),
    (f'MIDDLEWARE = [\n    # "{LOGIN}",\n]\n', False),                     # 주석
    (f'from django.contrib.auth.middleware import LoginRequiredMiddleware\nMIDDLEWARE = []\n', False),   # import만
])
def test_global_login_middleware(tmp_path, settings, guarded):
    hits = run(tmp_path, RoutesAnalyzer(), {"shop/urls.py": URLS, "shop/views.py": VIEW, "mysite/settings.py": settings})
    assert ("authz-no-auth-write" not in {h.rule_id for h in hits}) is guarded


@pytest.mark.parametrize("settings, guarded", [
    ('REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}\n', True),
    ('REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"]}\n', False),
    ('REST_FRAMEWORK = {}\n', False),                                      # DRF 기본값은 AllowAny
])
def test_drf_default_permission(tmp_path, settings, guarded):
    hits = run(tmp_path, RoutesAnalyzer(), {"shop/urls.py": DRF_URLS, "shop/views.py": DRF_VIEW, "mysite/settings.py": settings})
    labels = {(h.rule_id, h.extra["route"]) for h in hits}
    assert (("authz-no-auth-write", "POST /api/comments/bulk/") not in labels) is guarded


@pytest.mark.parametrize("files, kind", [
    ({"mysite/settings.py": 'ROOT_URLCONF = "mysite.urls"\n'}, "SESSION_COOKIE_SECURE,CSRF_COOKIE_SECURE"),
    ({"mysite/settings.py": 'ROOT_URLCONF = "mysite.urls"\nSESSION_COOKIE_SECURE = True\n'}, "CSRF_COOKIE_SECURE"),
    # 나눠 둔 settings: 운영 설정에만 있어도 된다
    ({"mysite/settings/base.py": 'ROOT_URLCONF = "mysite.urls"\n',
      "mysite/settings/prod.py": "from .base import *\nSESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\n"}, None),
    ({"app.py": "from flask import Flask\napp = Flask(__name__)\n"}, None),   # Django settings가 아니다
])
def test_missing_cookie_secure_settings(tmp_path, files, kind):
    hits = [h for h in run(tmp_path, ConfigAnalyzer(), files) if h.line == 0]
    assert [h.extra["kind"] for h in hits] == ([kind] if kind else [])
