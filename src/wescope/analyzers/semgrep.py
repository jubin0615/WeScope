"""WS-05 외: rules/semgrep의 자체 규칙만 오프라인으로 실행 (레지스트리 규칙·원격 통계 사용 안 함).

규칙 id가 `inject-xss--dom`처럼 `--`로 나뉘면 앞부분이 rule_id. metadata.confidence가 있으면 그 패턴의 신뢰도로 쓴다.
"""
import json
import os
import shutil
import subprocess
import sysconfig
from pathlib import Path

from wescope.analyzers.base import Analyzer, AnalyzerResult, ToolMissing
from wescope.models.finding import RawHit
from wescope.paths import RULES_DIR

# 테스트·예제 코드는 주입 검사에서 뺀다 (secrets의 테스트 파일 필터와 같은 기준)
_IGNORE = "\n".join(["tests/", "test/", "__tests__/", "fixtures/", "*.test.*", "*.spec.*", "test_*.py", "*_test.py",
                     ".semgrepignore"]) + "\n"


class SemgrepAnalyzer(Analyzer):
    id = "semgrep"
    categories = ("WS-05", "WS-02", "WS-06")
    languages = frozenset({"python", "javascript", "typescript"})

    def applies(self, ctx):
        return any(lang in ctx.profile.languages for lang in self.languages)

    def run(self, ctx) -> AnalyzerResult:
        exe = find_semgrep()
        if not exe:
            raise ToolMissing("semgrep이 설치되어 있지 않아요")
        # 사용자 저장소의 .semgrepignore나 semgrep 기본값에 결과가 흔들리지 않게 임시 스냅샷에 고정 목록을 쓴다
        (ctx.root / ".semgrepignore").write_text(_IGNORE, encoding="utf-8")
        proc = subprocess.run(
            [exe, "scan", "--config", str(RULES_DIR / "semgrep"), "--json", "--metrics=off", "--disable-version-check",
             "--no-git-ignore", "--quiet", "--timeout", "30", "."],
            cwd=ctx.root, capture_output=True, text=True, encoding="utf-8", timeout=600,
            env={**os.environ, "PYTHONUTF8": "1"})   # Windows 한국어 로케일(cp949)에서 한글 규칙 파일을 읽기 위해
        try:
            output = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(f"semgrep 실행 실패 (exit {proc.returncode})") from None
        hits = []
        for item in output["results"]:
            path = _relative(ctx, item["path"])
            meta = item["extra"].get("metadata", {})
            lines = (ctx.text(path) or "").splitlines()
            start, end = item["start"]["line"], item["end"]["line"]
            hits.append(RawHit(item["check_id"].rsplit(".", 1)[-1].split("--")[0], path, start,
                               evidence=lines[start - 1].strip() if start <= len(lines) else "",
                               end_line=end if end != start else None,
                               confidence=meta.get("variant_confidence")))
        broken = {_relative(ctx, e["path"]) for e in output.get("errors", []) if e.get("path")}
        ctx.partial_files.update(broken)
        if broken:
            return AnalyzerResult(hits, "partial", f"파일 {len(broken)}개를 해석하지 못함")
        return AnalyzerResult(hits)


def find_semgrep() -> str | None:
    """We-Scope를 실행한 Python의 스크립트 폴더를 PATH보다 먼저 본다.
    semgrep은 wescope와 함께 설치되는데, pipx·가상환경·pip --user 설치는 그 폴더가 PATH에 없을 수 있다."""
    own = [sysconfig.get_path("scripts"), sysconfig.get_path("scripts", sysconfig.get_preferred_scheme("user"))]
    return shutil.which("semgrep", path=os.pathsep.join(own)) or shutil.which("semgrep")


def _relative(ctx, path: str) -> str:
    full = Path(path)
    full = full if full.is_absolute() else ctx.root / full
    return full.resolve().relative_to(ctx.root.resolve()).as_posix()
