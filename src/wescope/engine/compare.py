"""직전 검사와 지문으로 비교: new / existing / fixed / unknown. 오탐 표시는 여기서 다루지 않는다(aggregate)."""
import copy


def compare(current, previous, partial_files, commit, excluded=()):
    """previous: 직전 ScanResult 또는 None. FIXED는 '직전 검사 대비'만 — 이미 fixed였던 것은 다시 싣지 않는다.

    excluded: 이번에 제외 패턴으로 뺀 파일·'폴더/'. 그 안의 이전 발견은 고친 게 아니라 검사 범위에서 뺀 것이므로
    fixed로 싣지 않고 결과에서 뺀다.
    """
    before = {f.fingerprint: f for f in (previous.findings if previous else []) if f.change != "fixed"}
    now = {f.fingerprint for f in current}
    for f in current:
        prev = before.get(f.fingerprint)
        f.change = "existing" if prev else "new"
        f.introduced_in = prev.introduced_in if prev else commit
    gone = []
    for fp, old in before.items():
        if fp in now or _excluded(old.location.file, excluded):
            continue
        old = copy.deepcopy(old)
        # 이번에 파싱하지 못한 파일의 발견은 해결로 보지 않는다
        old.change = "unknown" if old.location.file in partial_files else "fixed"
        gone.append(old)
    return current + gone


def _excluded(path: str, excluded) -> bool:
    return any(path == p or (p.endswith("/") and path.startswith(p)) for p in excluded)
