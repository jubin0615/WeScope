"""검사 범위 (RULES.md §5). JSON에는 상태 코드만 두고, 한국어 문구는 보고서·화면이 붙인다.

vulnerable 취약 후보 · clean 검사함·미발견 · partial 부분 점검 · not_applicable 해당 없음 · skipped 건너뜀 · manual 수동 확인 필요
"""
from wescope.models.scan_result import CoverageRow
from wescope.taxonomy import catalog

MANUAL_OWASP = {"A09:2025"}   # 정적 분석이 닿지 않는 영역


def ws_coverage(findings, statuses, profile) -> list[CoverageRow]:
    rows = []
    for area in catalog.ws_areas():
        code = area["code"]
        related = [s for s in statuses if code in s.categories]
        count = sum(f.category == code for f in findings)
        notes = [f"{s.id}: {s.note or s.status}" for s in related if s.status in ("skipped", "failed", "partial")]
        ran = [s for s in related if s.status != "not_applicable"]
        if not related:
            state, notes = "skipped", ["이 버전에서 아직 검사하지 않는 영역이에요"]
        elif count:
            state = "vulnerable"
        elif not ran:
            state = "not_applicable"
        elif all(s.status in ("skipped", "failed") for s in ran):
            state = "skipped"
        else:
            unsupported = _unsupported(ran, profile)
            notes += [f"규칙이 없는 언어: {', '.join(unsupported)}"] if unsupported else []
            rules = [r for r in catalog.rules().values() if r["category"] == code]
            absence_only = bool(rules) and all(r["confidence"] == "Potential" for r in rules)
            partial = notes or absence_only
            state = "partial" if partial else "clean"
        rows.append(CoverageRow(code, state, count, notes))
    return rows


def owasp_coverage(findings, ws_rows) -> list[CoverageRow]:
    by_ws = {row.code: row for row in ws_rows}
    rows = []
    for item in catalog.owasp_top10():
        code = item["code"]
        count = sum(f.owasp == code for f in findings)
        related = [by_ws[a["code"]].state for a in catalog.ws_areas() if code in a["owasp"]]
        if count:
            state = "vulnerable"
        elif code in MANUAL_OWASP or not related:
            state = "manual"
        elif all(s == "not_applicable" for s in related):
            state = "not_applicable"
        elif all(s in ("skipped", "not_applicable") for s in related):
            state = "skipped"
        elif all(s in ("clean", "not_applicable") for s in related):
            state = "clean"
        else:
            state = "partial"
        rows.append(CoverageRow(code, state, count, []))
    return rows


def _unsupported(statuses, profile) -> list[str]:
    supported = set().union(*(s.languages for s in statuses))
    if "*" in supported:
        return []
    return sorted(lang for lang in profile.languages if lang not in supported)
