"""~/.wescope/history.sqlite — 연결한 저장소·프로젝트 설정·검사 이력·발견 이력·오탐 표시.

코드 원문은 저장하지 않는다 (발견은 지문·규칙·위치·상태만).
"""
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from wescope.collector.snapshot import Target
from wescope.paths import home

# 목록의 i번째 스크립트가 user_version i+1을 만든다. 스키마를 바꿀 때는 기존 항목을 고치지 말고 뒤에 추가한다.
MIGRATIONS = [
    """
    CREATE TABLE repos (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, location TEXT NOT NULL, branch TEXT, name TEXT NOT NULL,
        disabled_rules TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL);
    CREATE TABLE scans (
        id TEXT PRIMARY KEY, repo_id TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        scanned_at TEXT NOT NULL, trigger TEXT NOT NULL, commit_sha TEXT, baseline TEXT,
        risk_score INTEGER NOT NULL, summary TEXT NOT NULL);
    CREATE INDEX scans_by_repo ON scans(repo_id);
    CREATE TABLE findings (
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL,
        rule_id TEXT NOT NULL, severity TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL,
        change TEXT NOT NULL, status TEXT NOT NULL, introduced_in TEXT, PRIMARY KEY (scan_id, fingerprint));
    CREATE TABLE ignores (
        repo_id TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, PRIMARY KEY (repo_id, fingerprint));
    """,
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _db():
    path = home() / "history.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=30)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        version = db.execute("PRAGMA user_version").fetchone()[0]
        for number, script in enumerate(MIGRATIONS[version:], version + 1):
            db.executescript(script)
            db.execute(f"PRAGMA user_version={number}")
        with db:          # 블록이 정상 종료되면 commit, 예외면 rollback
            yield db


def _repo(row) -> dict | None:
    return {**dict(row), "disabled_rules": json.loads(row["disabled_rules"])} if row else None


def add_repo(target: Target, name: str | None = None) -> dict:
    """저장소를 연결한다. 이미 연결돼 있으면 기존 것을 돌려준다. 폴더는 절대 경로로 맞춘다."""
    if target.kind == "folder":
        folder = Path(target.location).expanduser().resolve()
        if not folder.is_dir():
            raise ValueError(f"폴더를 찾을 수 없어요: {folder}")
        target = Target("folder", str(folder))
    elif target.kind != "github":
        raise ValueError(f"알 수 없는 종류: {target.kind}")
    default_name = Path(target.location.rstrip("/\\")).name.removesuffix(".git")
    with _db() as db:
        db.execute("INSERT OR IGNORE INTO repos (id, kind, location, branch, name, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                   (target.repo_id, target.kind, target.location, target.branch, name or default_name, _now()))
    repo = get_repo(target.repo_id)
    if (repo["kind"], repo["location"]) != (target.kind, target.location):   # 해시가 겹쳐도 남의 기록을 쓰지 않게
        raise ValueError(f"다른 저장소가 같은 id로 이미 연결돼 있어요: {repo['location']}")
    return repo


def get_repo(repo_id: str) -> dict | None:
    with _db() as db:
        return _repo(db.execute("SELECT * FROM repos WHERE id = ?", (repo_id,)).fetchone())


def list_repos() -> list[dict]:
    with _db() as db:
        return [_repo(r) for r in db.execute("SELECT * FROM repos ORDER BY created_at, id")]


def set_disabled_rules(repo_id: str, rules: list[str]):
    with _db() as db:
        db.execute("UPDATE repos SET disabled_rules = ? WHERE id = ?", (json.dumps(sorted(set(rules))), repo_id))


def remove_repo(repo_id: str):
    """연결 해제. 검사·발견·오탐 이력이 함께 지워진다 (결과 JSON은 results.purge)."""
    with _db() as db:
        db.execute("DELETE FROM repos WHERE id = ?", (repo_id,))


def record_scan(result):
    with _db() as db:
        db.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (result.scan_id, result.repo, result.scanned_at, result.trigger, result.commit, result.baseline_scan,
                    result.summary["risk_score"], json.dumps(result.summary, ensure_ascii=False)))
        db.executemany("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       [(result.scan_id, f.fingerprint, f.rule_id, f.severity, f.location.file, f.location.line,
                         f.change, f.status, f.introduced_in) for f in result.findings])


def latest_scan_id(repo_id: str) -> str | None:
    with _db() as db:
        row = db.execute("SELECT id FROM scans WHERE repo_id = ? ORDER BY rowid DESC LIMIT 1", (repo_id,)).fetchone()
        return row["id"] if row else None


def scans(repo_id: str, limit: int = 50) -> list[dict]:
    """최근 검사부터: 시각·트리거·커밋·점수·요약."""
    with _db() as db:
        rows = db.execute("SELECT * FROM scans WHERE repo_id = ? ORDER BY rowid DESC LIMIT ?", (repo_id, limit))
        return [{**dict(r), "summary": json.loads(r["summary"])} for r in rows]


def ignore(repo_id: str, fingerprint: str, reason: str = ""):
    with _db() as db:
        db.execute("INSERT OR REPLACE INTO ignores VALUES (?, ?, ?, ?)", (repo_id, fingerprint, reason, _now()))


def unignore(repo_id: str, fingerprint: str):
    with _db() as db:
        db.execute("DELETE FROM ignores WHERE repo_id = ? AND fingerprint = ?", (repo_id, fingerprint))


def ignored(repo_id: str) -> frozenset[str]:
    with _db() as db:
        return frozenset(r["fingerprint"] for r in db.execute("SELECT fingerprint FROM ignores WHERE repo_id = ?",
                                                               (repo_id,)))
