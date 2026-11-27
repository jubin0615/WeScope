"""Django urls.py(path·re_path·include) → view 함수·클래스 메서드 연결 (AST).

URL과 핸들러가 다른 파일에 있어 저장소의 Python 파일 전체를 한 번에 본다. 발견 위치는 고칠 곳인 view 쪽이다.
shortcut: DRF router(ViewSet)와 메서드를 직접 정의하지 않은 제네릭 뷰(DetailView 등)는 건너뛴다. 실제 앱에서 놓치는 게 보이면 추가.
"""
import ast
import re

from wescope.analyzers.routes.model import Route

_HTTP = ("get", "post", "put", "patch", "delete")
_ONLY = {"require_POST": ["POST"], "require_GET": ["GET"], "require_safe": ["GET"]}
# AllowAny는 '누구나 허용'이라 가드가 아니다 (ADMIN_HINT의 permission 단서에 걸리지 않게 지운다)
_ALLOW_ANY = re.compile(r"permission_classes\s*=\s*[\[(]\s*AllowAny\s*,?\s*[\])]")
_GLOBAL_LOGIN = "LoginRequiredMiddleware"   # Django 5.1+ 전역 로그인 강제


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
    global_guard = [_GLOBAL_LOGIN] if any(_GLOBAL_LOGIN in text for text, _ in files.values()) else []

    found, seen = [], set()
    for urls_file, route, name in patterns:
        target = _pick(defs.get(name, []), urls_file)
        if target is None or (target[0], target[1].lineno) in seen:   # 같은 view를 여러 URL에 걸어도 발견은 한 번
            continue
        file, node = target
        seen.add((file, node.lineno))
        text = files[file][0]
        url = "/" + "".join(_clean(p) for p in _prefix(includes, urls_file) + [route])
        if isinstance(node, ast.ClassDef):
            outer = [ast.unparse(b) for b in node.bases] + [ast.unparse(d) for d in node.decorator_list] + [
                ast.unparse(s) for s in node.body if isinstance(s, ast.Assign)]
            for meth in node.body:
                if isinstance(meth, ast.FunctionDef) and meth.name == "dispatch":
                    outer += [ast.unparse(d) for d in meth.decorator_list]
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
    guards = "\n".join(outer + [ast.unparse(d) for d in node.decorator_list])
    return Route(methods, url, file, start, (start, node.end_lineno), function, _ALLOW_ANY.sub("", guards),
                 ast.get_source_segment(text, node) or "", text.splitlines()[start - 1].strip())


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
