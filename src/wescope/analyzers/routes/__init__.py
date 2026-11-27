"""WS-02 인증·인가 누락: authz-admin-route · authz-idor · authz-no-auth-write.

모두 '가드가 없어 보인다'는 부재 추정이라 신뢰도는 항상 Potential (규칙 기본값).
"""
import re

from wescope.analyzers.base import Analyzer, AnalyzerResult
from wescope.analyzers.routes import django, express, python
from wescope.collector.inventory import language
from wescope.models.finding import RawHit, Scope

FRAMEWORKS = {"flask", "fastapi", "django", "express"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

ADMIN_PATH = re.compile(r"(?:^|/)(?:admin|internal|manage)(?:/|$|-|_)|/dashboard/admin", re.I)
ADMIN_HINT = re.compile(r"is_?admin|role\s*[!=]==?\s*['\"]admin|['\"]admin['\"]\s*[!=]==?|admin_required|require_?admin"
                        r"|require_?role|roles?_required|has_?role|permission|superuser|is_staff|staff_member|authori[sz]e", re.I)
AUTH_HINT = re.compile(r"login_?required|user_passes_test|jwt_required|token_required|auth|current_user|get_current_user|require_?login"
                       r"|is_authenticated|verify_?token|req\.user|request\.user|session\[|passport|protect"
                       r"|ensureLoggedIn|require_?user|getServerSession", re.I)
DB_WRITE = re.compile(r"\.(?:add|add_all|commit|delete|save|create|insert\w*|update\w*|destroy|remove|upsert|bulk_create"
                      r"|execute|findByIdAndUpdate|findOneAndUpdate|findByIdAndDelete|deleteOne|deleteMany)\s*\("
                      r"|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", re.I)
# 소유자 조건 = '현재 사용자'와 비교하는 단서. user_id 같은 이름만으로는 안 된다 (경로 파라미터 이름일 수 있음)
OWNER = re.compile(r"current_user|req\.user|request\.user|g\.user|session\[['\"]user|get_jwt_identity|auth\.uid|getServerSession")
NO_AUTH_PATHS = re.compile(r"(?:^|/)(?:login|signin|signup|register|logout|health|healthz|webhooks?|auth|callback)(?:/|$)", re.I)
_PARAM = re.compile(r"<(?:\w+:)?(\w+)>|\{(\w+)(?::[^}]*)?\}|:(\w+)")
_LOOKUP = (r"(?:\.(?:get|get_or_404|filter_by|filter|where|execute|query|find\w*|first_or_404|select|fetch\w*|scalar\w*)"
           r"|\bget_object_or_404)\s*\([^;]*?\b{}\b")


class RoutesAnalyzer(Analyzer):
    id = "routes"
    categories = ("WS-02",)
    languages = frozenset({"python", "javascript", "typescript"})

    def applies(self, ctx):
        return bool(FRAMEWORKS & set(ctx.profile.frameworks))

    def run(self, ctx) -> AnalyzerResult:
        hits, failed, python_files = [], 0, {}
        for path in ctx.text_files():
            lang = language(path)
            if lang == "python":
                tree = ctx.python_ast(path)
                if tree is None:
                    failed += 1
                    continue
                python_files[path] = (ctx.text(path), tree)
                found = python.routes(path, ctx.text(path), tree)
            elif lang in ("javascript", "typescript"):
                found = express.routes(path, ctx.text(path))
            else:
                continue
            for route in found:
                hits += judge(route)
        seen = set()   # Django는 한 view를 여러 URL에 걸 수 있어 URL마다 판정하고 같은 위치·규칙 발견은 하나로
        for route in django.routes(python_files) if "django" in ctx.profile.frameworks else []:
            for h in judge(route):
                if (h.rule_id, h.file, h.line) not in seen:
                    seen.add((h.rule_id, h.file, h.line))
                    hits.append(h)
        if failed:
            return AnalyzerResult(hits, "partial", f"Python 파일 {failed}개를 해석하지 못함")
        return AnalyzerResult(hits)


def judge(route) -> list[RawHit]:
    hints = route.guards + "\n" + route.body
    scope = Scope(route.function, route.label, route.span)

    def hit(rule):
        return RawHit(rule, route.file, route.line, evidence=route.evidence, scope=scope, extra={"route": route.label})

    hits = []
    is_admin = bool(ADMIN_HINT.search(hints))
    admin_path = bool(ADMIN_PATH.search(route.path))
    if admin_path and not is_admin:
        hits.append(hit("authz-admin-route"))
    # 관리자 경로는 원래 남의 데이터를 다루므로 IDOR 대신 관리자 확인(authz-admin-route)으로 본다
    if route.body and not admin_path and not is_admin and not OWNER.search(route.body):
        params = [next(g for g in groups if g) for groups in _PARAM.findall(route.path)]
        if any(re.search(_LOOKUP.format(re.escape(p)), route.body, re.S) for p in params):
            hits.append(hit("authz-idor"))
    if (WRITE_METHODS & set(route.methods) and route.body and DB_WRITE.search(route.body)
            and not AUTH_HINT.search(hints) and not is_admin and not NO_AUTH_PATHS.search(route.path)):
        hits.append(hit("authz-no-auth-write"))
    return hits
