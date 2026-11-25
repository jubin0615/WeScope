"""Express(app.get / router.post + 미들웨어 인자) 라우트 추출.

shortcut: 정규식 + 괄호 짝 맞추기로 읽는다. 핸들러를 다른 파일에서 가져오면 본문을 못 본다 → body가 비어 판정하지 않음.
라우트 체이닝(router.route("/x").get(...))이나 정규식 리터럴 안의 괄호가 문제되면 tree-sitter로 바꾼다.
"""
import re

from wescope.analyzers.routes.model import Route

_ROUTE = re.compile(r"\b(?:app|router|\w+Router|api|server)\s*\.\s*(get|post|put|patch|delete|all)\s*(\()\s*(['\"`])([^'\"`]+)\3")
_GLOBAL_USE = re.compile(r"\.use\(\s*(?:['\"`][^'\"`]*['\"`]\s*,\s*)?[^)]*?(?:auth|protect|passport\.authenticate|requireUser"
                         r"|verifyToken|isAuthenticated|ensureLoggedIn|jwt)", re.I)
_HANDLER_START = re.compile(r"=>|\bfunction\b")


def routes(path: str, text: str) -> list[Route]:
    uses = [m.start() for m in _GLOBAL_USE.finditer(text)]
    found = []
    for m in _ROUTE.finditer(text):
        open_at = m.start(2)
        close_at = _matching_paren(text, open_at)
        call = text[open_at:close_at + 1]
        after_path = call[m.end() - open_at:]
        handler = _HANDLER_START.search(after_path)
        guards = after_path[:handler.start()] if handler else after_path
        global_guard = "app.use(auth)" if any(u < m.start() for u in uses) else ""
        line = text.count("\n", 0, m.start()) + 1
        method = m.group(1).upper()
        found.append(Route(["GET", "POST", "PUT", "PATCH", "DELETE"] if method == "ALL" else [method], m.group(4),
                           path, line, (line, text.count("\n", 0, close_at) + 1), f"{method} {m.group(4)}",
                           guards + "\n" + global_guard, after_path if handler else "",
                           text.splitlines()[line - 1].strip()))
    return found


def _matching_paren(text: str, start: int) -> int:
    depth, i, quote = 0, start, None
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "/" and text[i + 1:i + 2] == "/":
            i = text.find("\n", i)
            if i < 0:
                break
            continue
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text) - 1
