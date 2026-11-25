"""Flask(@app.route, Blueprint) · FastAPI(@app.get, APIRouter, Depends) 라우트 추출 (AST)."""
import ast

from wescope.analyzers.routes.model import Route

_ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route"}
_GLOBAL_GUARD_CALLS = {"before_request", "before_app_request"}


def routes(path: str, text: str, tree: ast.Module) -> list[Route]:
    lines = text.splitlines()
    global_guards = _global_guards(text, tree)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if not (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)
                    and deco.func.attr in _ROUTE_DECORATORS and deco.args
                    and isinstance(deco.args[0], ast.Constant) and isinstance(deco.args[0].value, str)):
                continue
            methods = _methods(deco)
            others = [ast.unparse(d) for d in node.decorator_list if d is not deco]
            guards = "\n".join(others + [ast.unparse(k) for k in deco.keywords] + [ast.unparse(node.args)] + global_guards)
            found.append(Route(methods, deco.args[0].value, path, deco.lineno, (node.lineno, node.end_lineno),
                               node.name, guards, ast.get_source_segment(text, node) or "",
                               lines[deco.lineno - 1].strip()))
    return found


def _methods(deco: ast.Call) -> list[str]:
    if deco.func.attr in ("route", "api_route"):
        given = next((k.value for k in deco.keywords if k.arg == "methods"), None)
        if isinstance(given, (ast.List, ast.Tuple, ast.Set)):
            return sorted(e.value.upper() for e in given.elts if isinstance(e, ast.Constant))
        return ["GET"]
    return [deco.func.attr.upper()]


def _global_guards(text: str, tree: ast.Module) -> list[str]:
    """파일 전체에 걸리는 가드: before_request 함수, APIRouter/FastAPI(dependencies=[...])."""
    guards = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                (isinstance(d, ast.Attribute) and d.attr in _GLOBAL_GUARD_CALLS)
                or (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in _GLOBAL_GUARD_CALLS)
                for d in node.decorator_list):
            guards.append(ast.get_source_segment(text, node) or "")
        elif isinstance(node, ast.Call) and any(k.arg == "dependencies" for k in node.keywords) \
                and ast.unparse(node.func).split(".")[-1] in ("APIRouter", "FastAPI", "include_router"):
            guards.append(ast.unparse(node))
    return guards
