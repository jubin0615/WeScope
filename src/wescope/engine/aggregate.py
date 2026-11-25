"""사용자 표시(오탐·꺼 둔 규칙) 반영, 번호 부여, 검사 범위·점수·요약 → ScanResult."""
import uuid
from dataclasses import asdict
from datetime import datetime, timezone

from wescope.engine import coverage
from wescope.engine.normalize import sort_key
from wescope.engine.score import risk_score
from wescope.models.finding import SEVERITIES
from wescope.models.scan_result import ScanResult


def new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


def is_open(f) -> bool:
    """요약·점수·검사 범위에 세는 발견: 열려 있고 이번 검사에서 해결되지 않은 것."""
    return f.status == "open" and f.change != "fixed"


def aggregate(findings, statuses, ctx, *, ignored=frozenset(), disabled=frozenset(), trigger="manual",
              repo=None, baseline_scan=None, scan_id=None) -> ScanResult:
    for f in findings:
        if f.fingerprint in ignored or f.rule_id in disabled:
            f.status = "dismissed"     # 결과에는 남기고 점수·판정에서만 뺀다
    findings = sorted(findings, key=lambda f: (f.change == "fixed", sort_key(f)))
    for number, f in enumerate(findings, 1):
        f.id = f"F-{number:03d}"
    current = [f for f in findings if is_open(f)]
    ws_rows = coverage.ws_coverage(current, statuses, ctx.profile)
    summary = {
        "severity": {s: sum(f.severity == s for f in current) for s in SEVERITIES},
        "new": sum(f.change == "new" for f in current),
        "fixed": sum(f.change == "fixed" for f in findings),
        "dismissed": sum(f.status == "dismissed" for f in findings),
        "risk_score": risk_score(current),
        "skipped_files": len(ctx.skipped),
    }
    return ScanResult(
        scan_id=scan_id or new_scan_id(), scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        trigger=trigger, source=ctx.source, commit=ctx.source.get("commit"), baseline_scan=baseline_scan,
        profile=asdict(ctx.profile), analyzers=statuses, coverage=ws_rows,
        owasp_coverage=coverage.owasp_coverage(current, ws_rows), findings=findings, summary=summary, repo=repo)
