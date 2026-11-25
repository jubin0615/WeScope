"""직전 검사와 지문으로 비교: new / existing / fixed / unknown. 오탐 표시는 여기서 다루지 않는다(aggregate)."""
import copy


def compare(current, previous, partial_files, commit):
    """previous: 직전 ScanResult 또는 None. FIXED는 '직전 검사 대비'만 — 이미 fixed였던 것은 다시 싣지 않는다."""
    before = {f.fingerprint: f for f in (previous.findings if previous else []) if f.change != "fixed"}
    now = {f.fingerprint for f in current}
    for f in current:
        prev = before.get(f.fingerprint)
        f.change = "existing" if prev else "new"
        f.introduced_in = prev.introduced_in if prev else commit
    gone = []
    for fp, old in before.items():
        if fp not in now:
            old = copy.deepcopy(old)
            # 이번에 파싱하지 못한 파일의 발견은 해결로 보지 않는다
            old.change = "unknown" if old.location.file in partial_files else "fixed"
            gone.append(old)
    return current + gone
