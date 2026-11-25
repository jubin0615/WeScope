import json
from dataclasses import asdict, dataclass, field

from wescope.models.finding import Finding, Location, Scope

SCHEMA_VERSION = 1


@dataclass
class AnalyzerStatus:
    id: str
    categories: list[str]
    languages: list[str]
    status: str                       # ok / partial / skipped / failed / not_applicable
    elapsed: float = 0.0
    note: str = ""


@dataclass
class CoverageRow:
    code: str                         # WS-01 / A01:2025
    state: str                        # vulnerable / clean / partial / not_applicable / skipped / manual
    findings: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    scan_id: str
    scanned_at: str
    trigger: str                      # manual / hook
    source: dict
    commit: str | None
    baseline_scan: str | None
    profile: dict
    analyzers: list[AnalyzerStatus]
    coverage: list[CoverageRow]
    owasp_coverage: list[CoverageRow]
    findings: list[Finding]
    summary: dict
    repo: str | None = None
    ai: dict | None = None
    ai_coverage: list[CoverageRow] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "ScanResult":
        data = json.loads(text)
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"지원하지 않는 결과 형식: {data.get('schema_version')}")
        data["analyzers"] = [AnalyzerStatus(**a) for a in data["analyzers"]]
        for key in ("coverage", "owasp_coverage", "ai_coverage"):
            data[key] = [CoverageRow(**row) for row in data[key]]
        data["findings"] = [_finding(f) for f in data["findings"]]
        return cls(**data)


def _finding(data: dict) -> Finding:
    data["location"] = Location(**data["location"])
    if data["scope"]:
        scope = data["scope"]
        data["scope"] = Scope(scope["function"], scope["route"], tuple(scope["span"]) if scope["span"] else None)
    return Finding(**data)
