"""수정안용 맥락 수집 (AI.md §3-2). 로컬·결정론: 같은 코드면 같은 맥락(→ 같은 캐시 키).

보내는 것: 발견이 있는 파일(작으면 전체, 크면 import 구간 + 발견을 둘러싼 함수), 매니페스트, 규칙 지식.
shortcut: 다른 파일의 연관 정의(import 그래프 1단계)는 아직 보내지 않는다. 수정안이 다른 파일을 몰라 틀리면 추가
"""
import ast
from pathlib import PurePosixPath

from wescope.llm.guards import map_strings, suspicious

WHOLE_FILE = 16_000          # 이보다 작은 파일은 통째로
TOTAL = 48_000               # 넘으면 모든 파일을 발췌로 바꾼다 (발견 위치 함수는 항상 포함)
MANIFEST = 4_000
_MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml")
_AROUND = 40                 # 함수 범위를 모를 때 발견 앞뒤 줄 수


def numbered(lines: list[str], start: int, end: int) -> str:
    """'  36| 코드'. 모델이 diff의 줄 위치를 잡게 번호를 붙인다 (diff에는 번호를 넣지 말라고 지시한다)."""
    return "\n".join(f"{n:>5}| {lines[n - 1]}" for n in range(max(start, 1), min(end, len(lines)) + 1))


def _innermost(ctx, path: str, line: int):
    """(line을 감싸는 가장 안쪽 함수 노드, 그 함수까지의 이름 경로 예: ["OrderAPI", "get"]). Python만, 데코레이터 포함.
    없으면 (None, [])."""
    tree = ctx.python_ast(path) if path.endswith(".py") else None
    best = (None, [])

    def visit(node, names):
        nonlocal best
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = min([child.lineno, *(d.lineno for d in child.decorator_list)])
                if start <= line <= child.end_lineno:
                    if not isinstance(child, ast.ClassDef):
                        best = (child, names + [child.name])
                    visit(child, names + [child.name])     # 안쪽에 있으면 그쪽이 덮어쓴다
            else:
                visit(child, names)
    if tree is not None:
        visit(tree, [])
    return best


def span(ctx, path: str, line: int) -> tuple[int, int]:
    """발견 줄을 감싸는 가장 안쪽 함수(Python), 모르면 앞뒤 40줄."""
    node, _ = _innermost(ctx, path, line)
    if node is None:
        return line - _AROUND, line + _AROUND
    return min([node.lineno, *(d.lineno for d in node.decorator_list)]), node.end_lineno


def enclosing_def(ctx, path: str, line: int) -> str | None:
    """line을 감싸는 가장 안쪽 함수의 이름 경로 + def 줄 코드 (Python만). 예: "OrderAPI.get: def get(self, id):".
    같은 함수 안의 발견을 알아보는 열쇠로 쓴다. 이름 경로가 있어 다른 클래스의 같은 이름 메서드와 섞이지 않는다."""
    node, names = _innermost(ctx, path, line)
    lines = (ctx.text(path) or "").splitlines()
    if node is None or node.lineno > len(lines):
        return None
    return f"{'.'.join(names)}: {lines[node.lineno - 1].strip()}"


def local_imports(ctx, path: str) -> dict[str, dict[str, str]]:
    """Python 파일이 `from 모듈 import 이름`으로 가져오는 이 프로젝트 파일 → {쓰는 이름: 원래 이름}.
    상대 import(.)는 그 패키지 안만. 절대 import는 루트 기준(패키지로 실행)과 같은 폴더(파일을 직접 실행)가
    실행 방식에 따라 갈린다: 한쪽에만 있으면 그것, 둘 다 있으면 어느 쪽인지 모르므로 넣지 않는다
    (엉뚱한 파일을 맥락으로 보내면 판정이 틀린다. 모르면 빼는 게 낫다).
    shortcut: `from 모듈 import` 한 단계만. `import 모듈`·패키지 __init__·JS/TS import는 따라가지 않는다."""
    tree = ctx.python_ast(path) if path.endswith(".py") else None
    here = PurePosixPath(path).parent
    found: dict[str, dict[str, str]] = {}
    for node in getattr(tree, "body", []):
        if not isinstance(node, ast.ImportFrom) or not node.module or node.level > 1:
            continue
        module = node.module.replace(".", "/") + ".py"
        sibling = (here / module).as_posix()
        at = {c for c in ([sibling] if node.level else [module, sibling]) if c in ctx.files}
        if len(at) == 1:
            found.setdefault(at.pop(), {}).update({a.asname or a.name: a.name for a in node.names})
    return found


def excerpt(ctx, path: str, lines: list[str], hit_lines: list[int]) -> str:
    head = next((i for i, text in enumerate(lines) if text.startswith(("def ", "class ", "async def ", "@",
                                                                           "function ", "export ", "app."))), 30)
    spans = sorted([(1, max(head, 1))] + [span(ctx, path, n) for n in hit_lines if n > 0])
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return "\n  ...\n".join(numbered(lines, s, e) for s, e in merged)


def fix_payload(ctx, group, redactor, *, previous=None, rejected=None) -> tuple[dict, bool]:
    """(보낼 내용, 지시문 의심 여부). group은 같은 rule_id의 발견 목록."""
    first = group[0]
    by_file: dict[str, list[int]] = {}
    for f in group:
        by_file.setdefault(f.location.file, []).append(f.location.line)
    texts = {path: (ctx.text(path) or "") for path in sorted(by_file) if path in ctx.files}

    def files(whole: bool):
        out = []
        for path, text in texts.items():
            lines = text.splitlines()
            body = numbered(lines, 1, len(lines)) if whole and len(text) <= WHOLE_FILE else \
                excerpt(ctx, path, lines, by_file[path])
            out.append({"path": path, "excerpt": not (whole and len(text) <= WHOLE_FILE), "content": body})
        return out

    sent = files(whole=True)
    if sum(len(f["content"]) for f in sent) > TOTAL:
        sent = files(whole=False)
    manifests = {p: (ctx.text(p) or "")[:MANIFEST] for p in _MANIFESTS if p in ctx.files}
    payload = {
        "task": "fix",
        "project": {"frameworks": ctx.profile.frameworks, "languages": ctx.profile.languages, "manifests": manifests},
        "rule": {"rule_id": first.rule_id, "tech_name_ko": first.tech_name_ko, "severity": first.severity,
                 "cwe": first.cwe, "why_ko": first.why_ko, "fix_ko": first.fix_ko, "avoid_ko": first.avoid_ko,
                 "fix_example": first.fix_example},
        "locations": [{"file": f.location.file, "line": f.location.line, "route": f.location.route,
                       "evidence": f.evidence} for f in group],
        "files": sent,
        "previous_attempt": previous,     # 재요청: {"diff", "failures"}
        "rejected_diff": rejected,        # [다른 수정안]: 사용자가 채택하지 않은 diff
    }
    hidden = map_strings(payload, redactor.hide)
    return hidden, any(suspicious(f["content"]) for f in hidden["files"])

