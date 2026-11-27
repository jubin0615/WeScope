"""검사 중 ChatGPT 단계 (ARCHITECTURE §2): 보완 탐지(④, 심층만) → [엔진의 비교] → 의심 확인(③) → 수정안(①).

한 Session으로 요청 수·캐시 적중을 함께 센다. 로그인·자격·한도 문제(login·plan·limit)가 나면 다음 요청도 실패하므로
남은 일을 모두 멈추고, 그때까지의 결과는 둔다. 그 밖의 오류(error)는 그 항목만 건너뛴다.
"""
from wescope.llm import fixer, review, triage
from wescope.llm.cache import Session
from wescope.llm.client import LLMError
from wescope.llm.guards import Redactor


def _each(items, task, work, summary, progress) -> bool:
    """items마다 work. 멈춰야 하면 False. 하나가 실패해도 나머지는 계속한다."""
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


class Run:
    """한 검사의 ChatGPT 작업. 보완 탐지는 새 발견을 더하므로 엔진이 직전 결과와 비교(compare)하기 전에,
    의심 확인·수정안은 비교가 끝난 발견에 한다 (scan.run_scan이 순서를 잡는다). 한 Session으로 요청 수·캐시를 함께 센다."""

    def __init__(self, client, level: str):
        self.session = Session(client)
        self.level = level
        self.going = True
        self.reviewed: set[str] = set()          # 이번에 보완 탐지를 끝까지 한 대상 파일 (검사 범위 표)
        # 실제로 모델에 보낸 줄 {파일: 줄 번호들, 파일 전체면 None}. 직전 AI 발견을 '고쳐짐'으로 판단해도 되는 곳
        # (큰 파일은 발췌만 보내므로 파일 단위로 보면 모델이 못 본 발견까지 고쳐짐이 된다)
        self.seen: dict[str, set[int] | None] = {}
        self.coverage = []                       # 검사 범위 표의 AI 검토 행 (심층일 때만)
        self.summary = {"level": level, "model": None, "requests": 0, "cache_hits": 0, "review": None,
                        "triage": {"confirmed": 0, "protected": 0, "unclear": 0, "remaining": 0},
                        "fixes": {"verified": 0, "partial": 0, "failed": 0},
                        "budget_exceeded": False, "remaining_groups": 0, "error": None}

    def review(self, findings, ctx, *, progress=lambda *a, **k: None, limit: int | None = None) -> list:
        """보완 탐지 → 새 AI 발견 RawHit들. findings(정적 발견)에는 'ChatGPT도 지적' 근거를 붙일 수 있다."""
        if self.level != "deep":
            return []
        limit = review.AUTO_TARGETS if limit is None else limit
        candidates = review.targets(ctx)
        counts = self.summary["review"] = {"targets": 0, "found": 0, "merged": 0, "discarded": 0,
                                           "remaining": max(len(candidates) - limit, 0)}
        redactor = Redactor(ctx.secrets.values())
        hits = []

        def look(target):
            payload, suspects = review.review_payload(ctx, target, findings, redactor)
            answer, key = self.session.ask(review.INSTRUCTIONS, review.PROMPT_VERSION, payload, review.EFFORT,
                                           valid=review.well_formed)
            new, merged, dropped = review.check_answer(ctx, answer, {f["path"] for f in payload["files"]}, findings,
                                                       redactor, suspects, key)
            hits.extend(new)
            counts["found"] += len(new)
            counts["merged"] += merged
            counts["discarded"] += dropped
            counts["targets"] += 1
            self.reviewed.add(target["path"])
            for sent in payload["files"]:
                lines = review.sent_line_numbers(sent)
                old = self.seen.get(sent["path"], set())
                self.seen[sent["path"]] = None if lines is None or old is None else old | lines

        self.going = _each(candidates[:limit], "review", look, self.summary, progress)
        self.coverage = review.coverage(candidates, self.reviewed, hits)
        return hits

    def saw(self, path: str, line: int) -> bool:
        """이번 보완 탐지에서 그 줄을 모델에 보냈는가."""
        return path in self.seen and (self.seen[path] is None or line in self.seen[path])

    def check_and_fix(self, findings, ctx, rescan, *, skip=lambda f: False, progress=lambda *a, **k: None,
                      checks: int | None = None, groups: int | None = None) -> dict:
        """의심 확인 → 수정안. → 결과 JSON의 `ai` 요약. checks·groups: 스캔당 예산 (없으면 각 모듈의 AUTO_*)."""
        summary, session = self.summary, self.session
        checks = triage.AUTO_CHECKS if checks is None else checks
        groups = fixer.AUTO_GROUPS if groups is None else groups
        to_check = triage.targets(findings, skip)
        summary["triage"]["remaining"] = max(len(to_check) - checks, 0)

        def check(finding):
            summary["triage"][triage.check(session, ctx, finding)] += 1

        if self.going:
            self.going = _each(to_check[:checks], "triage", check, summary, progress)

        # ChatGPT가 보호 코드를 찾은(오탐 제안) 발견에는 수정안을 만들지 않는다
        proposed = lambda f: skip(f) or (f.triage or {}).get("suggested") == "dismiss"
        candidates = [g for g in fixer.groups(findings, proposed) if g[0].severity in fixer.AUTO_SEVERITIES]
        summary["remaining_groups"] = max(len(candidates) - groups, 0)

        def fix(group):
            group[0].fix = fixer.make_fix(session, ctx, group, findings, rescan)
            summary["fixes"][group[0].fix["verification"]] += 1

        if self.going:
            _each(candidates[:groups], "fix", fix, summary, progress)
        summary["budget_exceeded"] = bool(summary["triage"]["remaining"] or summary["remaining_groups"]
                                          or (summary["review"] or {}).get("remaining"))
        summary.update(session.stats, model=session.model)
        return summary
