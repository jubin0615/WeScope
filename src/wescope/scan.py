"""run_scan(): 파이프라인 조립. 서버 작업 큐·hook·테스트가 모두 이 함수를 부른다.

엔진은 저장소(store)·설정 파일을 모른다. 직전 결과·오탐 지문·꺼 둔 규칙은 scan_repo()가 store에서 읽어 넘긴다.
ChatGPT 검토·수정안(M3)과 체인 상관(M3)은 normalize 뒤·compare 앞 / compare 뒤 자리에 들어간다 (ARCHITECTURE §2).
"""
from wescope.analyzers.registry import analyzers
from wescope.collector.context import collect
from wescope.collector.snapshot import Target
from wescope.engine.aggregate import aggregate
from wescope.engine.compare import compare
from wescope.engine.normalize import normalize
from wescope.engine.runner import run_all
from wescope.models.scan_result import ScanResult
from wescope.store import history, results
from wescope.store.lock import scan_lock


def scan_repo(repo_id: str, *, trigger="manual", strict=False) -> ScanResult:
    """연결한 저장소를 검사하고 저장한다: 직전 결과와 비교, 오탐·꺼 둔 규칙 반영, 결과 JSON·이력 기록."""
    repo = history.get_repo(repo_id)
    if repo is None:
        raise KeyError(f"연결되지 않은 저장소: {repo_id}")
    with scan_lock():
        result = run_scan(Target(repo["kind"], repo["location"], repo["branch"]), previous=results.latest(repo_id),
                          ignored=history.ignored(repo_id), disabled=frozenset(repo["disabled_rules"]),
                          trigger=trigger, strict=strict)
        results.save(result)
        history.record_scan(result)
    return result


def run_scan(target: Target, *, previous: ScanResult | None = None, ignored=frozenset(), disabled=frozenset(),
             trigger="manual", strict=False) -> ScanResult:
    """저장 없이 검사만 한다 (테스트·수정안 검증용)."""
    with collect(target) as ctx:
        hits, statuses = run_all(ctx, analyzers(), strict=strict)
        findings = normalize(hits, ctx)
        findings = compare(findings, previous, ctx.partial_files, ctx.source.get("commit"))
        return aggregate(findings, statuses, ctx, ignored=ignored, disabled=disabled, trigger=trigger,
                         repo=target.repo_id, baseline_scan=previous.scan_id if previous else None)
