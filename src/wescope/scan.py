"""run_scan(): 파이프라인 조립. 서버 작업 큐·hook·테스트가 모두 이 함수를 부른다.

엔진은 저장소(store)·설정 파일을 모른다. 직전 결과·오탐 지문·꺼 둔 규칙은 scan_repo()가 store에서 읽어 넘긴다.
ChatGPT 수정안은 compare 뒤·aggregate 앞(ARCHITECTURE §2의 8번). 검토(5번)·체인(6번)은 B8-3·B8-4.
llm은 탐지기를 모르므로 수정안 재검사 함수(_rescan)를 여기서 넘긴다.
"""
from wescope.analyzers.registry import analyzers
from wescope.collector.context import collect
from wescope.collector.snapshot import Target
from wescope.engine.aggregate import aggregate
from wescope.engine.compare import compare
from wescope.engine.normalize import normalize
from wescope.engine.runner import run_all
from wescope.llm import client as llm_client
from wescope.llm import fixer
from wescope.llm.client import LLMError
from wescope.models.scan_result import ScanResult
from wescope.store import config, history, results
from wescope.store.lock import scan_lock

# 진행 단계 (대시보드 상태 문장 자리에 표시): 파일 수집 → 정적 분석 → 정리 → ChatGPT 분석(연결했을 때) → 저장
STAGES = ("collect", "analyze", "organize", "ai", "save")


def _quiet(stage: str, **detail):
    pass


def ai_client(trigger: str):
    """이번 검사에 쓸 ChatGPT. 설정에서 껐거나, 커밋 자동 검사인데 동의하지 않았거나, 로그인 전이면 None."""
    settings = config.load()
    if settings["ai_level"] == "off" or (trigger == "hook" and not settings["ai_on_hook"]):
        return None
    return llm_client.connected()


def scan_repo(repo_id: str, *, trigger="manual", strict=False, scan_id=None, progress=_quiet) -> ScanResult:
    """연결한 저장소를 검사하고 저장한다: 직전 결과와 비교, 오탐·꺼 둔 규칙·제외 패턴 반영, 결과 JSON·이력 기록."""
    repo = history.get_repo(repo_id)
    if repo is None:
        raise KeyError(f"연결되지 않은 저장소: {repo_id}")
    target = Target(repo["kind"], repo["location"], repo["branch"], tuple(repo["excludes"]))
    with scan_lock():
        result = run_scan(target, previous=results.latest(repo_id), ignored=history.ignored(repo_id),
                          disabled=frozenset(repo["disabled_rules"]), trigger=trigger, strict=strict,
                          scan_id=scan_id, progress=progress, ai=ai_client(trigger),
                          ai_level=config.load()["ai_level"])
        progress("save")
        results.save(result)
        history.record_scan(result)
    return result


def run_scan(target: Target, *, previous: ScanResult | None = None, ignored=frozenset(), disabled=frozenset(),
             trigger="manual", strict=False, scan_id=None, progress=_quiet, ai=None, ai_level="deep") -> ScanResult:
    """저장 없이 검사만 한다 (테스트·수정안 검증용). ai가 있으면 CRITICAL·HIGH 묶음에 수정안을 붙인다."""
    progress("collect")
    with collect(target) as ctx:
        progress("analyze")
        hits, statuses = run_all(ctx, analyzers(), strict=strict)
        progress("organize")
        findings = normalize(hits, ctx)
        findings = compare(findings, previous, ctx.partial_files, ctx.source.get("commit"), ctx.excluded)
        summary = None
        if ai is not None:
            progress("ai")
            summary = fixer.auto_fixes(findings, ctx, ai, _rescan, level=ai_level, progress=progress,
                                       skip=lambda f: f.fingerprint in ignored or f.rule_id in disabled)
        result = aggregate(findings, statuses, ctx, ignored=ignored, disabled=disabled, trigger=trigger,
                           repo=target.repo_id, baseline_scan=previous.scan_id if previous else None, scan_id=scan_id)
        result.ai = summary
        return result


def fix_group(repo_id: str, scan_id: str, rule_id: str, *, retry=False, progress=_quiet) -> ScanResult:
    """대시보드의 [수정안 만들기]·[다른 수정안]: 그 검사의 한 묶음에 수정안을 만들어 결과 JSON에 붙여 다시 저장한다.
    지금 파일 기준으로 만든다 (서버가 최신 검사에서만 받는다)."""
    client = llm_client.connected()
    if client is None:
        raise LLMError("ChatGPT에 연결하지 않았어요", "login")
    repo = history.get_repo(repo_id)
    result = results.load(repo_id, scan_id)
    group = next((g for g in fixer.groups(result.findings) if g[0].rule_id == rule_id), None)
    if repo is None or group is None:
        raise KeyError(f"수정할 위험 후보가 없어요: {rule_id}")
    rejected = group[0].fix["diff"] if retry and group[0].fix else None
    progress("ai", done=0, total=1)
    with collect(Target(repo["kind"], repo["location"], repo["branch"], tuple(repo["excludes"]))) as ctx:
        run_all(ctx, [a for a in analyzers() if a.id == "secrets"])   # 보내기 전에 가릴 비밀값을 다시 찾는다
        group[0].fix = fixer.make_fix(fixer.Session(client), ctx, group, result.findings, _rescan, rejected=rejected)
    progress("save")
    with scan_lock():
        results.save(result)
    return result


def _rescan(folder) -> list:
    """수정안을 적용한 사본을 같은 탐지기로 다시 검사한다 (llm.verify가 부른다)."""
    with collect(Target("folder", str(folder))) as ctx:
        hits, _ = run_all(ctx, analyzers())
        return normalize(hits, ctx)
