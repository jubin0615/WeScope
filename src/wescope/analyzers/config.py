"""WS-06 Python 설정 (AST): debug·ALLOWED_HOSTS·CORS·쿠키·서명 키·fail-open·예외 무시.
JS 쪽 CORS·쿠키·서명 키는 rules/semgrep/config-js.yml, 언어 무관 줄 패턴은 insecure_defaults.py."""
import ast
import re

from wescope.analyzers.base import Analyzer, AnalyzerResult
from wescope.analyzers.secrets.patterns import SIGNING_KEY_NAMES, WEAK_SIGNING_VALUES
from wescope.models.finding import RawHit

_SECURITY_FUNC = re.compile(r"auth|permission|verify|is_admin|check_access|authori[sz]e|require_|login_required")
_COOKIE_NAME = re.compile(r"session|token|auth|sid|jwt|remember", re.I)
_COOKIE_SETTINGS = {"SESSION_COOKIE_SECURE": False, "SESSION_COOKIE_HTTPONLY": False, "CSRF_COOKIE_SECURE": False,
                    "SESSION_COOKIE_SAMESITE": None, "REMEMBER_COOKIE_SECURE": False, "REMEMBER_COOKIE_HTTPONLY": False}
_COOKIE_FLAGS = (("secure", "CWE-614"), ("httponly", "CWE-1004"), ("samesite", "CWE-1275"))


def _const(node):
    return node.value if isinstance(node, ast.Constant) else ...


def _name(node) -> str:
    """대입 대상·호출 대상의 이름: DEBUG / app.debug → debug / app.config["DEBUG"] → DEBUG / CORS(...) → CORS"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript) and isinstance(_const(node.slice), str):
        return node.slice.value
    return ""


def _kw(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _kw_true(call: ast.Call, name: str) -> bool:
    value = _kw(call, name)
    return value is not None and _const(value) is True


def _has_star(node) -> bool:
    return node is not None and any(_const(n) in ("*", ".*") for n in ast.walk(node))


class ConfigAnalyzer(Analyzer):
    id = "config"
    categories = ("WS-06",)
    languages = frozenset({"python"})

    def applies(self, ctx):
        return "python" in ctx.profile.languages

    def run(self, ctx) -> AnalyzerResult:
        hits, failed = [], 0
        for path in ctx.text_files(".py"):
            tree = ctx.python_ast(path)
            if tree is None:
                failed += 1
                continue
            hits += _check(ctx, path, tree)
        if failed:
            return AnalyzerResult(hits, "partial", f"Python 파일 {failed}개를 해석하지 못함")
        return AnalyzerResult(hits)


def _check(ctx, path, tree):
    lines = ctx.text(path).splitlines()
    hits = []

    def hit(rule, node, **kw):
        hits.append(RawHit(rule, path, node.lineno, evidence=lines[node.lineno - 1].strip(), **kw))

    module_flags = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                _assignment(ctx, hit, _name(target), node, module_flags)
        elif isinstance(node, ast.Call):
            _call(ctx, hit, node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _SECURITY_FUNC.search(node.name.lower()):
            _exception_handling(hit, node)
    if module_flags.get("CORS_ALLOW_ALL_ORIGINS"):
        node = module_flags["CORS_ALLOW_ALL_ORIGINS"]
        hit("config-cors-credentials" if module_flags.get("CORS_ALLOW_CREDENTIALS") else "config-cors-wildcard", node)
    return hits


def _assignment(ctx, hit, name, node, module_flags):
    value = _const(node.value)
    upper = name.upper()
    if upper == "DEBUG" and value is True:
        hit("config-debug", node)
    elif upper == "ALLOWED_HOSTS" and _has_star(node.value):
        hit("config-allowed-hosts", node)
    elif upper in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL") and value is True:
        module_flags["CORS_ALLOW_ALL_ORIGINS"] = node
    elif upper == "CORS_ALLOW_CREDENTIALS" and value is True:
        module_flags["CORS_ALLOW_CREDENTIALS"] = node
    elif upper in _COOKIE_SETTINGS and value is _COOKIE_SETTINGS[upper] and isinstance(node.value, ast.Constant):
        cwe = "CWE-1275" if "SAMESITE" in upper else "CWE-1004" if "HTTPONLY" in upper else "CWE-614"
        hit("config-cookie-flags", node, extra={"cwe": cwe, "kind": upper})
    elif isinstance(value, str):
        _signing_key(ctx, hit, name, value, node)


def _signing_key(ctx, hit, name, value, node):
    if re.sub(r"[_\-]", "", name.lower()) not in SIGNING_KEY_NAMES:
        return
    # django-insecure-: startproject가 만든 개발용 키. 길어도 저장소에 그대로 있으면 누구나 안다
    if len(value) < 32 or value.lower() in WEAK_SIGNING_VALUES or value.startswith("django-insecure-"):
        if len(value) >= 8 and value.lower() not in WEAK_SIGNING_VALUES:
            ctx.secrets.register(value)   # 누구나 아는 기본값이 아니면 화면에 원문을 남기지 않는다
        hit("config-weak-secret", node)


def _call(ctx, hit, call):
    func = _name(call.func)
    if func in ("run", "Flask", "FastAPI", "Starlette") and _kw_true(call, "debug"):
        hit("config-debug", call)
    elif func == "update":   # app.config.update(DEBUG=True, SECRET_KEY="...")
        for k in call.keywords:
            if k.arg:
                _assignment(ctx, hit, k.arg, ast.Assign(targets=[], value=k.value, lineno=call.lineno), {})
    elif func == "CORS":
        origins = _kw(call, "origins") or _kw(call, "resources")
        if origins is None or _has_star(origins):   # flask-cors 기본값은 전체 허용
            hit("config-cors-credentials" if _kw_true(call, "supports_credentials") else "config-cors-wildcard", call)
    elif func == "add_middleware" and call.args and _name(call.args[0]) == "CORSMiddleware":
        if _has_star(_kw(call, "allow_origins")) or _has_star(_kw(call, "allow_origin_regex")):
            hit("config-cors-credentials" if _kw_true(call, "allow_credentials") else "config-cors-wildcard", call)
    elif func == "set_cookie":
        cookie = call.args[0] if call.args else _kw(call, "key")
        if isinstance(_const(cookie), str) and _COOKIE_NAME.search(cookie.value):
            # 변수로 넘긴 값은 알 수 없으므로 '없음'이나 리터럴 False/None만 누락으로 본다
            missing = [(flag, cwe) for flag, cwe in _COOKIE_FLAGS
                       if _kw(call, flag) is None or _const(_kw(call, flag)) in (None, False)]
            if missing:
                hit("config-cookie-flags", call, extra={"cwe": missing[0][1], "kind": ",".join(f for f, _ in missing)})


def _exception_handling(hit, func):
    for node in ast.walk(func):
        if not isinstance(node, ast.ExceptHandler):
            continue
        returns_true = [n for n in ast.walk(node) if isinstance(n, ast.Return) and _const(n.value) is True]
        if returns_true:
            hit("config-fail-open", returns_true[0])
        elif all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and _const(s.value) is Ellipsis) for s in node.body):
            hit("config-swallowed-exception", node)
