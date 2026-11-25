"""Analyzer 계약. 새 탐지기 = 이 클래스를 상속한 파일 1개 + registry.py 1줄 + 테스트."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from wescope.models.finding import RawHit


class ToolMissing(Exception):
    """외부 도구(semgrep 등)가 없어 실행할 수 없음 → skipped."""


@dataclass
class AnalyzerResult:
    hits: list[RawHit] = field(default_factory=list)
    status: str = "ok"                 # ok / partial / skipped / failed / not_applicable
    note: str = ""                     # 사유 (코드·비밀값을 넣지 않는다)


class Analyzer(ABC):
    id: str
    categories: tuple[str, ...]
    languages: frozenset[str]          # 검사 범위 계산용. 언어 무관이면 {"*"}

    def applies(self, ctx) -> bool:
        return True

    @abstractmethod
    def run(self, ctx) -> AnalyzerResult: ...
