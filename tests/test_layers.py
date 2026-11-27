"""의존성 방향 (DIRECTORY_STRUCTURE.md §2)을 import로 확인한다. 위반하면 구조가 다시 꼬이기 시작한 신호다."""
import ast
from pathlib import Path

SRC = Path(__file__).parent.parent / "src" / "wescope"

FORBIDDEN = {
    "models": ("wescope.collector", "wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.taxonomy",
               "wescope.store", "wescope.report"),
    "taxonomy": ("wescope.collector", "wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.store"),
    "collector": ("wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.store", "wescope.report"),
    "analyzers": ("wescope.engine", "wescope.scan", "wescope.store", "wescope.report", "wescope.llm"),
    "engine": ("wescope.analyzers.secrets", "wescope.analyzers.routes", "wescope.analyzers.semgrep",
               "wescope.analyzers.config", "wescope.analyzers.registry", "wescope.collector.snapshot", "wescope.scan",
               "wescope.store", "wescope.report", "wescope.llm"),
    # ChatGPT 분석은 Finding·ScanContext만 받는다. 재검사는 scan.py가 함수로 넘긴다 (DIRECTORY_STRUCTURE §2)
    "llm": ("wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.store", "wescope.server", "wescope.report",
            "wescope.collector"),
    # 저장·보고서는 결과를 옮길 뿐 판단하지 않는다
    "store": ("wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.report"),
    "report": ("wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.store", "wescope.collector"),
}
# 금지 아래에서 예외로 허용하는 모듈: 프로세스 간 잠금은 저장 계층이 아니라 공용 도구다 (토큰 갱신을 hook과 나눠 잠근다)
ALLOWED = {"llm": ("wescope.store.lock",)}


def imports(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
    return names


def test_dependency_direction():
    violations = []
    for package, banned in FORBIDDEN.items():
        for path in (SRC / package).rglob("*.py"):
            violations += [f"{path.relative_to(SRC)} → {name}" for name in imports(path)
                           if name.startswith(banned) and name not in ALLOWED.get(package, ())]
    assert violations == []
