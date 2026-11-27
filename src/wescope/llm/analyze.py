"""검사 중 ChatGPT 단계 (ARCHITECTURE §2): 의심 확인(③) → 수정안(①). 보완 탐지(④)는 B8-3b.

한 Session으로 요청 수·캐시 적중을 함께 센다. 로그인·자격·한도 문제(login·plan·limit)가 나면 다음 요청도 실패하므로
남은 일을 모두 멈추고, 그때까지의 결과는 둔다. 그 밖의 오류(error)는 그 항목만 건너뛴다.
"""
from wescope.llm import fixer, triage
from wescope.llm.cache import Session
from wescope.llm.client import LLMError


def _each(items, task, work, summary, progress) -> bool:
    """items마다 work. 멈춰야 하면 False."""
    for done, item in enumerate(items):
        progress("ai", task=task, done=done, total=len(items))
        try:
            work(item)
        except LLMError as error:
            summary["error"] = {"kind": error.kind, "message": str(error)}
            if error.kind != "error":
                return False
        except Exception as error:
            # 응답 형식을 놓친 곳이 있어도 이 항목만 실패로 남긴다. 검사가 통째로 멈추면 정적 결과도 저장되지 않고,
            # 그 응답은 캐시에 있어 다시 스캔해도 똑같이 멈춘다. 오류 종류 이름은 남겨 버그를 찾을 수 있게 한다
            summary["error"] = {"kind": "error", "message": f"ChatGPT 결과를 처리하지 못했어요 ({type(error).__name__})"}
    return True


def analyze(findings, ctx, client, rescan, *, level: str, skip=lambda f: False, progress=lambda *a, **k: None,
            checks: int | None = None, groups: int | None = None) -> dict:
    """→ 결과 JSON의 `ai` 요약. findings에 triage·fix를 붙이고, confirmed면 신뢰도를 올린다.
    checks·groups: 스캔당 예산 (없으면 triage.AUTO_CHECKS·fixer.AUTO_GROUPS)."""
    checks = triage.AUTO_CHECKS if checks is None else checks
    groups = fixer.AUTO_GROUPS if groups is None else groups
    session = Session(client)
    summary = {"level": level, "model": None, "requests": 0, "cache_hits": 0,
               "triage": {"confirmed": 0, "protected": 0, "unclear": 0, "remaining": 0},
               "fixes": {"verified": 0, "partial": 0, "failed": 0},
               "budget_exceeded": False, "remaining_groups": 0, "error": None}

    to_check = triage.targets(findings, skip)
    summary["triage"]["remaining"] = max(len(to_check) - checks, 0)

    def check(finding):
        summary["triage"][triage.check(session, ctx, finding)] += 1

    going = _each(to_check[:checks], "triage", check, summary, progress)

    # ChatGPT가 보호 코드를 찾은(오탐 제안) 발견에는 수정안을 만들지 않는다
    proposed = lambda f: skip(f) or (f.triage or {}).get("suggested") == "dismiss"
    candidates = [g for g in fixer.groups(findings, proposed) if g[0].severity in fixer.AUTO_SEVERITIES]
    summary["remaining_groups"] = max(len(candidates) - groups, 0)

    def fix(group):
        group[0].fix = fixer.make_fix(session, ctx, group, findings, rescan)
        summary["fixes"][group[0].fix["verification"]] += 1

    if going:
        _each(candidates[:groups], "fix", fix, summary, progress)
    summary["budget_exceeded"] = bool(summary["triage"]["remaining"] or summary["remaining_groups"])
    summary.update(session.stats, model=session.model)
    return summary
