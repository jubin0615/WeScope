"""Django urls.py(path·re_path·include) → view 함수·클래스 메서드 연결 (AST).

URL과 핸들러가 다른 파일에 있어 저장소의 Python 파일 전체를 한 번에 본다. 발견 위치는 고칠 곳인 view 쪽이다.
DRF router(`router.register`)의 ViewSet, 메서드를 상속받는 제네릭 뷰(DetailView·UpdateView·RetrieveUpdateDestroyAPIView·
ModelViewSet 등)는 상속받은 동작(조회·저장·삭제)을 판정용 본문으로 합성해 같은 judge()에 넘긴다.
shortcut: path()에 `ViewSet.as_view({"get": "list"})`로 직접 건 ViewSet은 건너뛴다. 실제 앱에서 보이면 추가.
"""
import ast
import re

from wescope.analyzers.routes.model import Route

_HTTP = ("get", "post", "put", "patch", "delete")
_ONLY = {"require_POST": ["POST"], "require_GET": ["GET"], "require_safe": ["GET"]}
# ViewSet 동작 → (HTTP 메서드, 상세(<pk>) 경로인지, DB 쓰기)
_ACTIONS = {"list": ("GET", False, None), "create": ("POST", False, "save"), "retrieve": ("GET", True, None),
            "update": ("PUT", True, "save"), "partial_update": ("PATCH", True, "save"),
            "destroy": ("DELETE", True, "delete")}
# 상속받는 기본 동작: 부모 클래스 이름 조각 → 동작 (ListCreateAPIView → list·create)
_PIECES = (("List", ("list",)), ("Create", ("create",)), ("Retrieve", ("retrieve",)), ("Detail", ("retrieve",)),
           ("Update", ("update", "partial_update")), ("Destroy", ("destroy",)), ("Delete", ("destroy",)))
_PARAM = re.compile(r"<(?:\w+:)?(\w+)>")


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
    # patterns: (view를 찾을 기준 파일, URL 접두어를 물려받는 urls 파일, 경로 조각, view 이름, router 등록인지)
    patterns, includes, defs, registrations, mounts, imports = [], {}, {}, [], [], {}
    for file, (_, tree) in files.items():
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defs.setdefault(node.name, []).append((file, node))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):              # from api.router import router
                module = node.module or ""
                if node.level:                                 # from .router import router → 같은 폴더의 router.py
                    folder = file.rsplit("/", node.level)[0] if file.count("/") >= node.level else ""
                    module = f"{folder}/{module}".strip("/").replace("/", ".")
                imports.setdefault(file, {}).update({a.asname or a.name: module for a in node.names})
            if not isinstance(node, ast.Call):
                continue
            call = node
            # router.register(r"orders", OrderViewSet) — admin.site.register(Model)은 첫 인자가 문자열이 아니라 빠진다
            if (_name(call.func) == "register" and isinstance(call.func, ast.Attribute) and len(call.args) >= 2
                    and _str(call.args[0]) is not None):
                registrations.append((file, _name(call.func.value), call.args[0].value, _name(call.args[1])))
            if not (_name(call.func) in ("path", "re_path", "url") and len(call.args) >= 2
                    and _str(call.args[0]) is not None):
                continue
            view = call.args[1]
            if isinstance(view, ast.Call) and _name(view.func) == "include":
                if view.args and isinstance(view.args[0], ast.Attribute) and view.args[0].attr == "urls":
                    mounts.append((file, _name(view.args[0].value), call.args[0].value))   # include(router.urls)
                elif target := _module_file(files, _str(view.args[0]) if view.args else None):
                    includes[target] = (file, call.args[0].value)
            else:
                patterns.append((file, file, [call.args[0].value], _name(view), False))
    # router 접두어는 router 변수로 잇는다: 연결한 파일에서 만들었거나, 그 파일이 import한 모듈에서 만든 같은 이름의 router
    mounted = set()
    for mount_file, var, prefix in mounts:
        source = mount_file if any(f == mount_file and v == var for f, v, _, _ in registrations) \
            else _module_file(files, imports.get(mount_file, {}).get(var))
        for reg in registrations:
            if reg[0] == source and reg[1] == var:
                patterns.append((reg[0], mount_file, [prefix, reg[2].strip("^$/") + "/"], reg[3], True))
                mounted.add(reg)
    patterns += [(f, f, [route.strip("^$/") + "/"], name, True)       # 연결한 곳을 못 찾으면 접두어 없이
                 for f, v, route, name in registrations if (f, v, route, name) not in mounted]
    login = ["LoginRequiredMiddleware"] if _login_middleware(files) else []
    drf_default = _drf_default(files)

    # 같은 view가 여러 URL에 걸리면 URL마다 판정한다 (관리자 경로인지는 URL에 달렸다). 겹친 발견은 부르는 쪽이 합친다
    found = []
    for pick_file, urls_file, route_parts, name, router in patterns:
        target = _pick(defs.get(name, []), pick_file)
        if target is None:
            continue
        file, node = target
        url = "/" + "".join(_clean(p) for p in _prefix(includes, urls_file) + route_parts)
        if isinstance(node, ast.ClassDef):
            found += _class_routes(files, defs, file, node, url, router, login, drf_default)
        else:
            text = files[file][0]
            guards = login + ([drf_default] if any(_name(d) == "api_view" for d in node.decorator_list)
                              and not any(_name(d) == "permission_classes" for d in node.decorator_list) else [])
            found.append(_route(file, text, node, _methods(node, ast.get_source_segment(text, node) or ""), url,
                                node.name, guards))
    return found


def _lineage(files, defs, file, node, seen=()):
    """클래스와 저장소 안에 정의된 부모 클래스들 [(파일, ClassDef)] — 부모에 둔 permission_classes·메서드도 물려받는다.
    shortcut: 깊이 우선 순서라 다이아몬드 상속에선 Python MRO와 다를 수 있다. 실제 앱에서 보이면 C3로."""
    chain = [(file, node)]
    for base in node.bases:
        parent = _pick(defs.get(_name(base), []), file)
        if parent and isinstance(parent[1], ast.ClassDef) and parent[1].name not in seen:
            chain += _lineage(files, defs, *parent, (*seen, node.name))
    return chain


def _class_routes(files, defs, file, node, url, router, login, drf_default) -> list[Route]:
    lineage = _lineage(files, defs, file, node)
    bases = [_name(b) for _, cls in lineage for b in cls.bases]
    drf = any("APIView" in b or "ViewSet" in b or b.endswith("ModelMixin") for b in bases)
    outer = list(bases) + login
    for _, cls in lineage:
        outer += [_guard(d) for d in cls.decorator_list]
        outer += [_guard(s) for s in cls.body if isinstance(s, ast.Assign) and not _assigns(s, "permission_classes")]
        outer += [_guard(d) for m in cls.body if isinstance(m, ast.FunctionDef) and m.name == "dispatch"
                  for d in m.decorator_list]
    # DRF permission_classes는 합쳐지지 않고 덮어쓴다: 상속 순서상 가장 가까운 클래스의 것 하나, 없으면 settings 기본 권한
    own = next((s for _, cls in lineage for s in cls.body if _assigns(s, "permission_classes")), None)
    perm = _guard(own) if own is not None else drf_default if drf else ""
    methods = {}                                      # 이름 → (파일, 정의) — 자식 클래스 정의가 먼저
    for cls_file, cls in reversed(lineage):
        methods |= {m.name: (cls_file, m) for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}

    found, outer = [], outer + [perm]
    if router:
        lookup = next((_str(s.value) for _, cls in lineage for s in cls.body if _assigns(s, "lookup_field")), None)
        detail_url = f"{url}<{lookup or 'pk'}>/"
        for action, (http, detail, write) in _ACTIONS.items():
            if action in methods:
                meth_file, meth = methods[action]
                found.append(_route(meth_file, files[meth_file][0], meth, [http], detail_url if detail else url,
                                    f"{node.name}.{action}", outer))
            elif action in _implicit(bases):
                found.append(_implicit_route(files, file, node, lineage, methods, action, [http],
                                             detail_url if detail else url, detail, write, outer))
        for name, (meth_file, meth) in methods.items():       # @action(detail=True, methods=["post"])
            deco = next((d for d in meth.decorator_list if isinstance(d, ast.Call) and _name(d.func) == "action"), None)
            if deco is not None:
                kw = {k.arg: k.value for k in deco.keywords}
                http = [e.value.upper() for e in getattr(kw.get("methods"), "elts", []) if _str(e)] or ["GET"]
                detail = isinstance(kw.get("detail"), ast.Constant) and kw["detail"].value is True
                # @action(permission_classes=[...])는 클래스 권한을 덮어쓴다 (데코레이터 쪽 이름은 _guard가 남긴다)
                guards = outer[:-1] if "permission_classes" in kw else outer
                found.append(_route(meth_file, files[meth_file][0], meth, http,
                                    f"{detail_url if detail else url}{_str(kw.get('url_path')) or name}/",
                                    f"{node.name}.{name}", guards))
        return found
    for name in _HTTP:
        if name in methods:
            meth_file, meth = methods[name]
            found.append(_route(meth_file, files[meth_file][0], meth, [name.upper()], url, f"{node.name}.{name}", outer))
    for action in sorted(_implicit(bases)):
        http, detail, write = _ACTIONS[action]
        # Django 제네릭 뷰는 쓰기를 POST 폼으로 받는다.
        # shortcut: UpdateView·DeleteView가 post()만 덮어쓰면 상속받은 GET 화면의 조회는 보지 않는다. 실제 앱에서 보이면 GET을 따로
        if not drf:
            http = "POST" if write else "GET"
        if http.lower() not in methods:
            found.append(_implicit_route(files, file, node, lineage, methods, action, [http], url, detail, write, outer))
    return found


def _implicit(bases) -> set[str]:
    acts = set()
    for name in bases:
        if "ModelViewSet" in name:
            acts |= {"list", "retrieve"} if "ReadOnly" in name else set(_ACTIONS)
        elif name.endswith(("View", "Mixin")):
            acts |= {a for piece, group in _PIECES if piece in name for a in group}
    return acts


def _implicit_route(files, file, node, lineage, methods, action, http, url, detail, write, outer) -> Route:
    """상속받은 동작의 판정용 본문: get_queryset·get_object 원문 + 기본 queryset + 하는 일(조회·저장·삭제) 한 줄씩.
    get_queryset에서 request.user로 거르면 judge()의 소유자 단서로 잡힌다."""
    text = files[file][0]
    start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
    body = [ast.get_source_segment(files[f][0], m) or "" for name, (f, m) in methods.items()
            if name in ("get_queryset", "get_object")]
    body += [ast.unparse(s) for _, cls in lineage for s in cls.body if _assigns(s, "queryset") or _assigns(s, "model")]
    param = next(iter(_PARAM.findall(url)), None)
    if detail and param:
        body.append(f"obj = self.get_queryset().get({param}={param})")
    if write:
        body.append(f"obj.{write}()")
    return Route(http, url, file, start, (start, node.end_lineno), f"{node.name}.{action}", "\n".join(outer),
                 "\n".join(body), text.splitlines()[start - 1].strip())


def _assigns(node, name) -> bool:
    """클래스 본문 대입문(또는 클래스 안 어디든) `name = ...` 인지."""
    if isinstance(node, ast.ClassDef):
        return any(_assigns(s, name) for s in node.body)
    return isinstance(node, ast.Assign) and any(_name(t) == name for t in node.targets)


def _drf_default(files) -> str:
    """settings REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]의 클래스 이름. 없으면 DRF 기본값 AllowAny(= 단서 없음).
    `REST_FRAMEWORK = {...}` 대입문 안의 키만 본다 (테스트·다른 dict의 같은 키는 앱 설정이 아니다)."""
    for _, tree in files.values():
        for node in tree.body:
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                    and any(_name(t) == "REST_FRAMEWORK" for t in node.targets)
                    and "DEFAULT_PERMISSION_CLASSES" in (keys := [_str(k) for k in node.value.keys])):
                value = node.value.values[keys.index("DEFAULT_PERMISSION_CLASSES")]
                names = [(_str(e) or ast.unparse(e)).split(".")[-1] for e in ast.walk(value) if _str(e) or isinstance(e, ast.Name)]
                return " ".join(n for n in names if n != "AllowAny")
    return ""


def _route(file, text, node, methods, url, function, outer) -> Route:
    start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
    guards = "\n".join(outer + [_guard(d) for d in node.decorator_list])
    return Route(methods, url, file, start, (start, node.end_lineno), function, guards,
                 ast.get_source_segment(text, node) or "", text.splitlines()[start - 1].strip())


def _guard(node) -> str:
    """가드 단서 원문. DRF permission_classes는 클래스 이름만 남긴다: 'permission'이라는 글자가 관리자 확인으로 읽히지 않게
    (IsAuthenticated → 로그인 단서, IsAdminUser → 관리자 단서, AllowAny → 단서 없음)."""
    keyword = next((k.value for k in getattr(node, "keywords", []) if k.arg == "permission_classes"), None)
    if isinstance(node, ast.Assign) and any(_name(t) == "permission_classes" for t in node.targets):
        source = ast.unparse(node.value)
    elif isinstance(node, ast.Call) and _name(node.func) == "permission_classes":
        source = " ".join(ast.unparse(a) for a in node.args)
    elif isinstance(node, ast.Call) and keyword is not None:      # @action(..., permission_classes=[...])
        source = ast.unparse(keyword)
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
    if re.search(r"request\.(POST|FILES|body)\b", body):
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
