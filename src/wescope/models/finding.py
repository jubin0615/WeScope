"""엔진이 만드는 데이터 구조. JSON 변환은 scan_result.py에서만 한다."""
from dataclasses import dataclass, field

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def lower_severity(severity: str) -> str:
    return SEVERITIES[min(SEVERITIES.index(severity) + 1, len(SEVERITIES) - 1)]


@dataclass
class Scope:
    function: str | None = None
    route: str | None = None          # "POST /admin/users"
    span: tuple[int, int] | None = None


@dataclass
class RawHit:
    """Analyzer 출력. severity·confidence가 None이면 규칙 기본값을 쓴다."""
    rule_id: str
    file: str
    line: int                         # 0 = 파일 단위 발견 (.env 커밋, .gitignore 없음 등)
    evidence: str = ""
    end_line: int | None = None
    severity: str | None = None
    confidence: str | None = None
    scope: Scope | None = None
    source: str = "engine"            # engine / ai
    extra: dict = field(default_factory=dict)


@dataclass
class Location:
    file: str
    line: int
    end_line: int | None = None
    route: str | None = None


@dataclass
class Finding:
    rule_id: str
    category: str
    cwe: str | None
    owasp: str | None
    severity: str
    confidence: str
    title_ko: str
    tech_name_ko: str
    why_ko: str
    fix_ko: str
    avoid_ko: str
    fix_example: str
    limitations_ko: str
    location: Location
    evidence: str
    fingerprint: str
    id: str = ""
    owasp_ai: list[str] = field(default_factory=list)
    source: str = "engine"
    confidence_source: str = "flow"   # flow / absence / ai_confirmed / ai
    scope: Scope | None = None
    extra: dict = field(default_factory=dict)
    change: str = "new"               # new / existing / fixed / unknown
    introduced_in: str | None = None
    status: str = "open"              # open / dismissed
    triage: dict | None = None        # M3
    fix: dict | None = None           # M3
    chain: str | None = None          # M3
    related: list[str] = field(default_factory=list)
