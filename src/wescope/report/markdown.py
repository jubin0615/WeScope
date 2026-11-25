"""ScanResult → 한국어 Markdown 보고서 (HOW_IT_WORKS.md 9단계 구성). 판단하지 않고 결과 JSON만 옮긴다."""
from pathlib import PurePath

from wescope.models.finding import SEVERITIES
from wescope.report import wording as W
from wescope.taxonomy import catalog


def render(result) -> str:
    ws_names = {a["code"]: a["name_ko"] for a in catalog.ws_areas()}
    owasp_names = {o["code"]: o["name"] for o in catalog.owasp_top10()}
    ws_order = list(ws_names)
    current = [f for f in result.findings if f.status == "open" and f.change != "fixed"]
    fixed = [f for f in result.findings if f.change == "fixed"]
    summary = result.summary
    source = result.source
    name = PurePath(source["location"].rstrip("/\\")).name or source["location"]
    out = [f"# 보안 진단 보고서 — {name} @ {(result.commit or '커밋 없음')[:7]}", "",
           f"- 진단 일시: {result.scanned_at}",
           f"- 대상: {W.SOURCE_KO[source['kind']]} `{source['location']}`" + (" (Git)" if source.get("git") else ""),
           f"- 진단 방식: 정적 분석 · ChatGPT 분석 사용 안 함 · {W.TRIGGER_KO[result.trigger]}",
           "", f"> {W.NOT_A_GUARANTEE}", "",
           "## 1. 요약", "",
           "| 위험 점수 | " + " | ".join(SEVERITIES) + " |", "|---" * (len(SEVERITIES) + 1) + "|",
           f"| {summary['risk_score']} | " + " | ".join(str(summary["severity"][s]) for s in SEVERITIES) + " |", "",
           (f"- 직전 검사 대비: NEW {summary['new']} · FIXED {summary['fixed']}" if result.baseline_scan
            else "- 첫 검사예요. 다음 검사부터 새로 생긴 위험(NEW)과 해결된 위험(FIXED)을 비교해요."),
           f"- 오탐으로 표시한 항목: {summary['dismissed']}개 (상세에서 뺐어요)", ""]
    if current:
        out += ["### 지금 고칠 것 Top 3", ""]
        out += [f"{i}. **{f.severity}** {f.title_ko} — `{_where(f)}`" for i, f in enumerate(current[:3], 1)] + [""]

    out += ["## 2. 발견 상세 (규칙별)", ""]
    if not current:
        out += ["열린 발견이 없어요. 검사 범위(4장)에서 확인하지 못한 영역을 함께 보세요.", ""]
    groups: dict[str, list] = {}
    for f in current:                        # current는 이미 심각도 순 → 그룹의 첫 항목이 가장 심각
        groups.setdefault(f.rule_id, []).append(f)
    for items in sorted(groups.values(), key=lambda g: (ws_order.index(g[0].category), SEVERITIES.index(g[0].severity))):
        f = items[0]
        owasp = f"OWASP {f.owasp} {owasp_names[f.owasp]}" if f.owasp else "OWASP Top 10 범위 밖"
        out += [f"### [{f.severity}] {f.tech_name_ko} — {len(items)}곳", "",
                f"- 분류: {f.category} {ws_names[f.category]} · {owasp} · {f.cwe or 'CWE 없음'}", "",
                f"**무엇이** {f.title_ko}", "", f"**왜 위험한가** {f.why_ko}", "", f"**어떻게 고치나** {f.fix_ko}",
                "", f"**하지 말 것** {f.avoid_ko}", "", "**위치**", ""]
        for item in items:
            notes = [item.confidence] + ([item.severity] if item.severity != f.severity else [])
            notes += [W.CHANGE_KO[item.change]] if item.change == "unknown" or (item.change == "new" and result.baseline_scan) else []
            notes += [f"라우트 `{item.location.route}`"] if item.location.route else []
            out += [f"- `{_where(item)}` · {' · '.join(notes)}"]
            out += ["", *("  " + line for line in _code(item.evidence)), ""] if item.evidence else []
        out += ["", "수정 예시:", "", *_code(f.fix_example.rstrip()), "", f"**이 결과가 증명하지 않는 것** {f.limitations_ko}", ""]

    if fixed:
        out += ["## 3. 이번에 해결된 항목", ""]
        out += [f"- **{f.severity}** {f.tech_name_ko} — `{_where(f)}`" for f in fixed] + [""]

    out += ["## 4. 검사 범위", "", "### We-Scope Top 10", "", "| 영역 | 상태 | 발견 | 사유 |", "|---|---|---|---|"]
    out += [f"| {r.code} {ws_names[r.code]} | {W.STATE_KO[r.state]} | {r.findings} | {_cell('; '.join(r.notes))} |"
            for r in result.coverage]
    out += ["", f"### {W.OWASP_SCOPE_TITLE}", "", "| 카테고리 | 상태 | 발견 |", "|---|---|---|"]
    out += [f"| {r.code} {owasp_names[r.code]} | {W.STATE_KO[r.state]} | {r.findings} |" for r in result.owasp_coverage]
    out += ["", "### 검사기", "", "| 검사기 | 맡은 영역 | 상태 | 사유 |", "|---|---|---|---|"]
    out += [f"| {a.id} | {', '.join(a.categories)} | {W.ANALYZER_STATUS_KO[a.status]} | {_cell(a.note)} |"
            for a in result.analyzers]

    out += ["", "## 5. 한계와 다음 확인 사항", ""] + [f"- {line}" for line in W.LIMITS]
    if summary["skipped_files"]:
        out += [f"- 읽지 못하고 건너뛴 파일이 {summary['skipped_files']}개 있어요 (5MB 초과·UTF-8 아님·심볼릭 링크)."]
    return "\n".join(out) + "\n"


def _where(f) -> str:
    return f.location.file if f.location.line <= 0 else f"{f.location.file}:{f.location.line}"


def _code(text: str) -> list[str]:
    fence = "~~~~" if "```" in text else "```"
    return [fence, text, fence]


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
