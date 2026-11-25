import time

from wescope.analyzers.base import AnalyzerResult, ToolMissing
from wescope.models.scan_result import AnalyzerStatus


def run_all(ctx, analyzers, strict=False):
    """고정 순서로 실행. 하나가 실패해도 나머지는 계속한다 (strict면 예외를 그대로 올림).

    shortcut: Analyzer별 타임아웃 없음 (외부 도구는 subprocess timeout으로 막음). 순수 Python 탐지기가 느려지면 프로세스 분리.
    """
    hits, statuses = [], []
    for analyzer in analyzers:
        started = time.monotonic()
        if not analyzer.applies(ctx):
            result = AnalyzerResult(status="not_applicable")
        else:
            try:
                result = analyzer.run(ctx)
            except ToolMissing as error:
                result = AnalyzerResult(status="skipped", note=str(error))
            except Exception as error:
                if strict:
                    raise
                result = AnalyzerResult(status="failed", note=type(error).__name__)
        hits.extend(result.hits)
        statuses.append(AnalyzerStatus(analyzer.id, list(analyzer.categories), sorted(analyzer.languages),
                                       result.status, round(time.monotonic() - started, 3), result.note))
    return hits, statuses
