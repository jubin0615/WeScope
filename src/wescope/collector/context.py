"""ScanContext: 모든 Analyzer가 공유하는 한 번만 만든 수집 결과."""
import ast
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from wescope.collector import snapshot as snap
from wescope.collector.inventory import AppProfile, build


class SecretRegistry:
    """이번 스캔에서 찾은 비밀값. 모든 출력은 mask()를 거친다. 원문은 메모리에만 있다."""

    def __init__(self):
        self._masks: dict[str, str] = {}

    def register(self, value: str) -> str:
        masked = value[:4] + "••••"
        self._masks[value] = masked
        return masked

    def mask(self, text: str) -> str:
        for value in sorted(self._masks, key=len, reverse=True):
            text = text.replace(value, self._masks[value])
        return text


@dataclass
class ScanContext:
    root: Path
    source: dict
    files: list[str]
    all_files: list[str]
    sensitive_files: list[dict]
    git_status: dict[str, str] | None
    skipped: dict[str, str]
    excluded: list[str] = field(default_factory=list)   # 제외 패턴에 걸린 파일·'폴더/'
    secrets: SecretRegistry = field(default_factory=SecretRegistry)
    profile: AppProfile = field(default_factory=AppProfile)
    partial_files: set[str] = field(default_factory=set)
    _texts: dict = field(default_factory=dict, repr=False)
    _asts: dict = field(default_factory=dict, repr=False)

    def text(self, path: str) -> str | None:
        """텍스트 파일 내용 (지연 로딩·캐시). 바이너리·인코딩 실패는 None + skipped 기록."""
        if path not in self._texts:
            self._texts[path] = None
            raw = (self.root / path).read_bytes()
            if b"\0" not in raw[:8192]:   # NUL이 있으면 바이너리
                try:
                    self._texts[path] = raw.decode("utf-8-sig").replace("\r\n", "\n")
                except UnicodeDecodeError:
                    self.skipped[path] = "UTF-8이 아님"
        return self._texts[path]

    def python_ast(self, path: str) -> ast.Module | None:
        if path not in self._asts:
            self._asts[path] = None
            source = self.text(path)
            if source is not None:
                try:
                    self._asts[path] = ast.parse(source)
                except SyntaxError:
                    self.partial_files.add(path)
        return self._asts[path]

    def text_files(self, *suffixes: str) -> list[str]:
        return [p for p in self.files if (not suffixes or p.endswith(suffixes)) and self.text(p) is not None]


@contextmanager
def collect(target: snap.Target):
    """임시 스냅샷을 만들고, 블록이 끝나면(실패해도) 지운다."""
    work = Path(tempfile.mkdtemp(prefix="wescope-"))
    try:
        root = work / "root"
        root.mkdir()
        s = snap.take(target, root)
        ctx = ScanContext(root, s.source, s.files, s.all_files, s.sensitive_files, s.git_status, s.skipped, s.excluded)
        ctx.profile = build(ctx)
        yield ctx
    finally:
        shutil.rmtree(work, ignore_errors=True)
