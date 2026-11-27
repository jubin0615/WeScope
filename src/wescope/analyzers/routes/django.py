"""Django urls.py(path·re_path·include) → view 함수·클래스 메서드 연결 (AST).

URL과 핸들러가 다른 파일에 있어 저장소의 Python 파일 전체를 한 번에 본다. 발견 위치는 고칠 곳인 view 쪽이다.
shortcut: DRF router(ViewSet)와 메서드를 직접 정의하지 않은 제네릭 뷰(DetailView 등)는 건너뛴다. 실제 앱에서 놓치는 게 보이면 추가.
"""
import ast
import re

from wescope.analyzers.routes.model import Route

_HTTP = ("get", "post", "put", "patch", "delete")
_ONLY = {"require_POST": ["POST"], "require_GET": ["GET"], "require_safe": ["GET"]}


def _name(node) -> str:
    """views.search → search, OrderAPI.as_view() → OrderAPI, login_required(...) → login_required"""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
            return _name(node.func.value)
        return _name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def routes(files: dict[str, tuple[str, ast.Module]]) -> list[Route]:
    """files: {경로: (원문, AST)} — 저장소의 모든 Python 파일."""
    patterns, includes, defs = [], {}, {}
    for file, (_, tree) in files.items():
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defs.setdefault(node.name, []).append((file, node))
        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call) and _name(call.func) in ("path", "re_path", "url")
                    and len(call.args) >= 2 and _str(call.args[0]) is not None):
                continue
            view = call.args[1]
            if isinstance(view, ast.Call) and _name(view.func) == "include":
                target = _module_file(files, _str(view.args[0]) if view.args else None)
                if target:
                    includes[target] = (file, call.args[0].value)
            else:
                patterns.append((file, call.args[0].value, _name(view)))
    global_guard = ["LoginRequiredMiddleware"] if _login_middleware(files) else []

    # 같은 view가 여러 URL에 걸리면 URL마다 판정한다 (관리자 경로인지는 URL에 달렸다). 겹친 발견은 부르는 쪽이 합친다
    found = []
    for urls_file, route, name in patterns:
        target = _pick(defs.get(name, []), urls_file)
        if target is None:
            continue
        file, node = target
        text = files[file][0]
        url = "/" + "".join(_clean(p) for p in _prefix(includes, urls_file) + [route])
        if isinstance(node, ast.ClassDef):
            outer = [ast.unparse(b) for b in node.bases] + [_guard(d) for d in node.decorator_list] + [
                _guard(s) for s in node.body if isinstance(s, ast.Assign)]
            for meth in node.body:
                if isinstance(meth, ast.FunctionDef) and meth.name == "dispatch":
                    outer += [_guard(d) for d in meth.decorator_list]
            for meth in node.body:
                if isinstance(meth, (ast.FunctionDef, ast.AsyncFunctionDef)) and meth.name in _HTTP:
                    found.append(_route(file, text, meth, [meth.name.upper()], url, f"{node.name}.{meth.name}",
                                        outer + global_guard))
        else:
            found.append(_route(file, text, node, _methods(node, ast.get_source_segment(text, node) or ""), url,
                                node.name, global_guard))
    return found


def _route(file, text, node, methods, url, function, outer) -> Route:
    start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
    guards = "\n".join(outer + [_guard(d) for d in node.decorator_list])
    return Route(methods, url, file, start, (start, node.end_lineno), function, guards,
                 ast.get_source_segment(text, node) or "", text.splitlines()[start - 1].strip())


def _guard(node) -> str:
    """가드 단서 원문. DRF permission_classes는 클래스 이름만 남긴다: 'permission'이라는 글자가 관리자 확인으로 읽히지 않게
    (IsAuthenticated → 로그인 단서, IsAdminUser → 관리자 단서, AllowAny → 단서 없음)."""
    if isinstance(node, ast.Assign) and any(_name(t) == "permission_classes" for t in node.targets):
        source = ast.unparse(node.value)
    elif isinstance(node, ast.Call) and _name(node.func) == "permission_classes":
        source = " ".join(ast.unparse(a) for a in node.args)
    else:
        return ast.unparse(node)
    names = [word.split(".")[-1] for word in re.findall(r"[\w.]+", source)]   # permissions.IsAuthenticated → IsAuthenticated
    return " ".join(n for n in names if n != "AllowAny")


def _login_middleware(files) -> bool:
    """settings의 MIDDLEWARE 목록에 LoginRequiredMiddleware(Django 5.1+ 전역 로그인)가 실제로 있을 때만. import·주석은 아니다."""
    for _, tree in files.values():
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AugAssign)) and any(
                    _name(t) == "MIDDLEWARE" for t in (node.targets if isinstance(node, ast.Assign) else [node.target])):
                if any((_str(n) or "").endswith(".LoginRequiredMiddleware") for n in ast.walk(node.value)):
                    return True
    return False


def _methods(node, body: str) -> list[str]:
    """함수 view는 모든 메서드를 받는다. 제한 데코레이터가 없으면 본문에서 다루는 메서드를 추정한다."""
    for deco in node.decorator_list:
        name = _name(deco)
        if name in _ONLY:
            return _ONLY[name]
        if name in ("require_http_methods", "api_view") and isinstance(deco, ast.Call) and deco.args \
                and isinstance(deco.args[0], (ast.List, ast.Tuple)):
            return sorted({e.value.upper() for e in deco.args[0].elts if _str(e)})
    found = {"GET"} | {m.upper() for m in re.findall(r"request\.method\s*==\s*['\"](\w+)['\"]", body)}
    if re.search(r"request\.(POST|FILES)\b", body):
        found.add("POST")
    return sorted(found)


def _module_file(files, module):
    if not module:
        return None
    tail = module.replace(".", "/") + ".py"
    return next((f for f in sorted(files) if f == tail or f.endswith("/" + tail)), None)


def _prefix(includes, file, seen=()) -> list[str]:
    if file not in includes or file in seen:
        return []
    parent, prefix = includes[file]
    return _prefix(includes, parent, (*seen, file)) + [prefix]


def _clean(part: str) -> str:
    return part.removeprefix("^").removesuffix("$")


def _pick(candidates, urls_file):
    """같은 이름이 여러 앱에 있으면 urls.py와 같은 폴더의 것을 고른다. 정할 수 없으면 건너뛴다."""
    folder = urls_file.rpartition("/")[0]
    same = [c for c in candidates if c[0].rpartition("/")[0] == folder]
    if len(same) == 1:
        return same[0]
    return candidates[0] if len(candidates) == 1 else None
