"""Django 전역 로그인(LoginRequiredMiddleware)은 settings의 MIDDLEWARE 목록에 실제로 있을 때만 가드로 본다."""
import pytest

from wescope.analyzers.routes import RoutesAnalyzer
from wescope.collector.context import collect
from wescope.collector.snapshot import Target

VIEW = ('from django.views.decorators.http import require_POST\nfrom .models import Comment\n\n'
        '@require_POST\ndef add_comment(request):\n    Comment.objects.create(body=request.POST["b"])\n')
LOGIN = "django.contrib.auth.middleware.LoginRequiredMiddleware"


@pytest.mark.parametrize("settings, guarded", [
    (f'MIDDLEWARE = ["{LOGIN}"]\n', True),
    (f'MIDDLEWARE = []\nMIDDLEWARE += ["{LOGIN}"]\n', True),
    (f'MIDDLEWARE = [\n    # "{LOGIN}",\n]\n', False),                     # 주석
    (f'from django.contrib.auth.middleware import LoginRequiredMiddleware\nMIDDLEWARE = []\n', False),   # import만
])
def test_global_login_middleware(tmp_path, settings, guarded):
    for rel, text in {"shop/urls.py": 'from django.urls import path\nfrom . import views\n'
                                      'urlpatterns = [path("comments/", views.add_comment)]\n',
                      "shop/views.py": VIEW, "mysite/settings.py": settings}.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    with collect(Target("folder", str(tmp_path))) as ctx:
        rules = {h.rule_id for h in RoutesAnalyzer().run(ctx).hits}
    assert ("authz-no-auth-write" not in rules) is guarded
