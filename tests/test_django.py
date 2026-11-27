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


DRF_HEAD = ("from rest_framework import viewsets\nfrom rest_framework.views import APIView\nfrom rest_framework.decorators import action\n"
            "from rest_framework.permissions import AllowAny, IsAuthenticated\nfrom .models import Comment\n\n")
WRITE = "        Comment.objects.create(body=request.data['b'])\n"


@pytest.mark.parametrize("parent, child, guarded", [
    ("IsAuthenticated", "AllowAny", False),            # 자식이 덮어쓰면 부모 권한은 사라진다
    ("AllowAny", "IsAuthenticated", True),
    ("IsAuthenticated", None, True),                   # 덮어쓰지 않으면 부모 것을 물려받는다
])
def test_permission_classes_are_overridden_not_merged(tmp_path, parent, child, guarded):
    own = f"    permission_classes = [{child}]\n\n" if child else ""
    views = (DRF_HEAD + f"class BaseAPI(APIView):\n    permission_classes = [{parent}]\n\n"
             f"class CommentAPI(BaseAPI):\n{own}    def post(self, request):\n{WRITE}")
    hits = run(tmp_path, RoutesAnalyzer(), {"shop/views.py": views, "shop/urls.py":
               'from django.urls import path\nfrom . import views\nurlpatterns = [path("c/", views.CommentAPI.as_view())]\n'})
    assert ("authz-no-auth-write" not in {h.rule_id for h in hits}) is guarded


@pytest.mark.parametrize("cls, act, guarded", [
    ("IsAuthenticated", "AllowAny", False),            # action 권한이 클래스 권한을 덮어쓴다
    ("AllowAny", "IsAuthenticated", True),
    ("IsAuthenticated", None, True),
])
def test_action_permission_overrides_class(tmp_path, cls, act, guarded):
    kw = f", permission_classes=[{act}]" if act else ""
    views = (DRF_HEAD + f"class CommentViewSet(viewsets.GenericViewSet):\n    permission_classes = [{cls}]\n\n"
             f'    @action(detail=False, methods=["post"]{kw})\n    def bulk(self, request):\n{WRITE}')
    hits = run(tmp_path, RoutesAnalyzer(), {"shop/views.py": views, "shop/urls.py": DRF_URLS})
    assert ("authz-no-auth-write" not in {h.rule_id for h in hits}) is guarded


def test_router_prefix_follows_the_router_variable(tmp_path):
    """다른 파일에서 만든 router(상대 import 포함), 한 urls.py에 접두어가 다른 router 둘."""
    views = (DRF_HEAD + "class UserViewSet(viewsets.ModelViewSet):\n    queryset = Comment.objects.all()\n"
             "    permission_classes = [IsAuthenticated]\n\n"
             "class CommentViewSet(viewsets.ReadOnlyModelViewSet):\n    queryset = Comment.objects.all()\n")
    hits = run(tmp_path, RoutesAnalyzer(), {
        "shop/views.py": views,
        "api/routers.py": "from rest_framework.routers import DefaultRouter\nfrom shop.views import UserViewSet\n"
                          'admin_router = DefaultRouter()\nadmin_router.register(r"users", UserViewSet)\n',
        "api/urls.py": "from django.urls import include, path\nfrom rest_framework.routers import DefaultRouter\n"
                       "from shop.views import CommentViewSet\nfrom .routers import admin_router\n"
                       'public = DefaultRouter()\npublic.register(r"comments", CommentViewSet)\n'
                       'urlpatterns = [path("manage/", include(admin_router.urls)), path("v1/", include(public.urls))]\n',
    })
    labels = {h.extra["route"] for h in hits}
    assert "GET /manage/users/" in labels and "GET /v1/comments/<pk>/" in labels
    assert not any(label.startswith(("GET /users", "GET /manage/comments", "GET /v1/users")) for label in labels)
