"""의존성 방향 (DIRECTORY_STRUCTURE.md §2)을 import로 확인한다. 위반하면 구조가 다시 꼬이기 시작한 신호다."""
import ast
from pathlib import Path

SRC = Path(__file__).parent.parent / "src" / "wescope"

FORBIDDEN = {
    "models": ("wescope.collector", "wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.taxonomy",
               "wescope.store", "wescope.report"),
    "taxonomy": ("wescope.collector", "wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.store"),
    "collector": ("wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.store", "wescope.report"),
    "analyzers": ("wescope.engine", "wescope.scan", "wescope.store", "wescope.report"),
    "engine": ("wescope.analyzers.secrets", "wescope.analyzers.routes", "wescope.analyzers.semgrep",
               "wescope.analyzers.config", "wescope.analyzers.registry", "wescope.collector.snapshot", "wescope.scan",
               "wescope.store", "wescope.report"),
    # 저장·보고서는 결과를 옮길 뿐 판단하지 않는다
    "store": ("wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.report"),
    "report": ("wescope.analyzers", "wescope.engine", "wescope.scan", "wescope.store", "wescope.collector"),
}


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
            violations += [f"{path.relative_to(SRC)} → {name}" for name in imports(path) if name.startswith(banned)]
    assert violations == []
