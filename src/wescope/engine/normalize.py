"""RawHit → Finding: 규칙 메타 결합, CWE→OWASP, 마스킹, 지문, 중복 병합, 정렬."""
import ast
import hashlib
import re

from wescope.models.finding import SEVERITIES, Finding, Location
from wescope.taxonomy import catalog, owasp


def sort_key(f: Finding):
    return (SEVERITIES.index(f.severity), f.location.file, f.location.line, f.rule_id)


def code_identity(ctx, hit) -> str:
    """줄 번호 대신 코드 내용으로 같은 발견을 알아본다. 비밀값은 마스킹한 뒤 쓴다.
    탐지기가 extra["identity"]를 주면 그것을 쓴다 (예: ChatGPT 보완 탐지는 인용 줄이 매번 달라질 수 있어 함수 단위로)."""
    if hit.extra.get("identity"):
        return f"{hit.file}|{ctx.secrets.mask(hit.extra['identity'])}"
    if hit.line <= 0:   # 파일 단위 발견
        return f"{hit.file}|{hit.extra.get('kind', '')}"
    lines = (ctx.text(hit.file) or "").splitlines()
    line = ctx.secrets.mask(lines[hit.line - 1].strip() if hit.line <= len(lines) else hit.evidence)
    if hit.file.endswith(".py"):
        try:
            return ast.unparse(ast.parse(line))   # 따옴표·공백 차이 제거
        except SyntaxError:
            pass                                  # 여러 줄 문장의 일부
    return re.sub(r"\s+", " ", line)


def fingerprint(rule_id: str, file: str, identity: str) -> str:
    return hashlib.sha256(f"{rule_id}|{file}|{identity}".encode()).hexdigest()[:16]


def normalize(hits, ctx) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for hit in hits:
        rule = catalog.rule(hit.rule_id)
        fp = fingerprint(hit.rule_id, hit.file, code_identity(ctx, hit))
        if fp in findings:
            continue          # 같은 규칙·같은 코드 → 하나로
        confidence = hit.confidence or rule["confidence"]
        cwe = hit.extra.get("cwe") or rule["cwe"]
        findings[fp] = Finding(
            rule_id=hit.rule_id, category=rule["category"], cwe=cwe, owasp=owasp.classify(cwe),
            owasp_ai=list(rule["owasp_ai"]), severity=hit.severity or rule["severity"], confidence=confidence,
            title_ko=rule["title_ko"], tech_name_ko=rule["tech_name_ko"], why_ko=rule["why_ko"],
            fix_ko=rule["fix_ko"], avoid_ko=rule["avoid_ko"], fix_example=rule["fix_example"],
            limitations_ko=rule["limitations_ko"],
            location=Location(hit.file, hit.line, hit.end_line, hit.scope.route if hit.scope else None),
            evidence=ctx.secrets.mask(hit.evidence), fingerprint=fp, source=hit.source,
            confidence_source="flow" if confidence == "Likely" else "absence",
            scope=hit.scope, extra={k: ctx.secrets.mask(str(v)) for k, v in hit.extra.items()})
    return sorted(findings.values(), key=sort_key)
