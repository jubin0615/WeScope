import sqlite3
import subprocess
import sys
import threading

import pytest

from conftest import materialize
from wescope.collector.snapshot import Target
from wescope.scan import scan_repo
from wescope.store import history, results
from wescope.store.lock import scan_lock


@pytest.fixture
def no_semgrep(monkeypatch):
    """저장 동작만 보는 테스트는 Semgrep 없이 빠르게 돈다."""
    monkeypatch.setattr("wescope.analyzers.semgrep.shutil.which", lambda _: None)


def test_scan_repo_saves_and_compares(tmp_path, no_semgrep):
    root, _ = materialize("vuln_flask", tmp_path)
    repo = history.add_repo(Target("folder", str(root)))
    assert history.add_repo(Target("folder", str(root / "." ))) == repo          # 같은 폴더는 한 번만 연결
    first = scan_repo(repo["id"])
    assert first.repo == repo["id"] and first.baseline_scan is None
    assert results.load(repo["id"], first.scan_id) == first

    app = root / "app.py"
    app.write_text(app.read_text(encoding="utf-8").replace("app.run(debug=True)", "app.run()"), encoding="utf-8")
    second = scan_repo(repo["id"], trigger="hook")
    assert second.baseline_scan == first.scan_id                                    # 직전 결과와 비교했다
    assert second.summary["fixed"] == 1 and second.summary["new"] == 0
    assert [s["id"] for s in history.scans(repo["id"])] == [second.scan_id, first.scan_id]
    assert history.scans(repo["id"])[0]["trigger"] == "hook"
    assert results.latest(repo["id"]) == second


def test_ignores_and_disabled_rules_apply_on_next_scan(tmp_path, no_semgrep):
    root, _ = materialize("vuln_flask", tmp_path)
    repo = history.add_repo(Target("folder", str(root)))
    first = scan_repo(repo["id"])
    target = next(f for f in first.findings if f.rule_id == "authz-idor")
    history.ignore(repo["id"], target.fingerprint, "소유자 확인은 서비스 계층에서 해요")
    history.update_settings(repo["id"], disabled_rules=["config-security-todo"])
    second = scan_repo(repo["id"])
    status = {f.fingerprint: f.status for f in second.findings}
    assert status[target.fingerprint] == "dismissed"
    assert {f.status for f in second.findings if f.rule_id == "config-security-todo"} == {"dismissed"}
    assert second.summary["dismissed"] == 2

    history.unignore(repo["id"], target.fingerprint)
    assert {f.fingerprint: f.status for f in scan_repo(repo["id"]).findings}[target.fingerprint] == "open"


def test_excluding_a_folder_does_not_mark_its_findings_fixed(tmp_path, no_semgrep):
    """리뷰: 대시보드에서 제외 패턴을 넣으면 그 폴더의 위험이 '해결됨'으로 보이던 문제."""
    root, _ = materialize("vuln_flask", tmp_path)
    (root / "legacy").mkdir()
    (root / "legacy" / "old.py").write_text("DEBUG = True\n")
    repo = history.add_repo(Target("folder", str(root)))
    first = scan_repo(repo["id"])
    assert any(f.location.file == "legacy/old.py" for f in first.findings)
    history.update_settings(repo["id"], excludes=["legacy/"])
    second = scan_repo(repo["id"])
    assert not [f for f in second.findings if f.location.file.startswith("legacy/")]
    assert second.summary["fixed"] == 0


def test_dashboard_excludes_win_over_wescopeignore_negation(tmp_path, no_semgrep):
    """리뷰: .wescopeignore의 '!' 줄이 대시보드 제외 설정을 무르던 문제."""
    root = tmp_path / "app"
    (root / "gen").mkdir(parents=True)
    (root / "gen" / "out.py").write_text("DEBUG = True\n")
    (root / ".wescopeignore").write_text("!gen/out.py\n")
    repo = history.add_repo(Target("folder", str(root)))
    history.update_settings(repo["id"], excludes=["gen/out.py"])
    assert scan_repo(repo["id"]).findings == []


def test_migration_runs_once_under_concurrent_first_open(tmp_path):
    """리뷰: v1 DB를 여러 곳이 동시에 처음 열면 ALTER가 두 번 돌아 'duplicate column'으로 실패하던 문제."""
    (tmp_path / "home").mkdir()                       # conftest의 WESCOPE_HOME
    db = sqlite3.connect(tmp_path / "home" / "history.sqlite")
    for statement in history.MIGRATIONS[0].split(";"):
        if statement.strip():
            db.execute(statement)
    db.execute("PRAGMA user_version=1")
    db.commit()
    db.close()
    errors = []

    def open_once():
        try:
            history.list_repos()
        except Exception as error:   # noqa: BLE001 — 어떤 오류든 실패로 센다
            errors.append(error)

    threads = [threading.Thread(target=open_once) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    with sqlite3.connect(tmp_path / "home" / "history.sqlite") as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == len(history.MIGRATIONS)
        assert "excludes" in [row[1] for row in check.execute("PRAGMA table_info(repos)")]


def test_remove_repo_clears_history(tmp_path, no_semgrep):
    root, _ = materialize("clean_app", tmp_path)
    repo = history.add_repo(Target("folder", str(root)))
    scan_repo(repo["id"])
    history.remove_repo(repo["id"])
    results.purge(repo["id"])
    assert history.get_repo(repo["id"]) is None and history.latest_scan_id(repo["id"]) is None
    assert results.latest(repo["id"]) is None


def test_similar_paths_stay_separate_repos(tmp_path, no_semgrep):
    """PR #1 리뷰: /app/one과 /app_one이 같은 id가 되어 남의 폴더를 검사하던 문제."""
    one, other = tmp_path / "app" / "one", tmp_path / "app_one"
    for folder, code in ((one, "DEBUG = True\n"), (other, "x = 1\n")):
        folder.mkdir(parents=True)
        (folder / "settings.py").write_text(code)
    a, b = history.add_repo(Target("folder", str(one))), history.add_repo(Target("folder", str(other)))
    assert a["id"] != b["id"] and b["location"] == str(other.resolve())
    assert [f.rule_id for f in scan_repo(a["id"]).findings] == ["config-debug"]
    assert scan_repo(b["id"]).findings == []
    assert len(history.scans(a["id"])) == 1 and len(history.scans(b["id"])) == 1


def test_path_with_consecutive_dots_is_saved(tmp_path, no_semgrep):
    """PR #1 리뷰: app..old 같은 폴더가 분석 후 저장 단계에서 실패하던 문제."""
    folder = tmp_path / "app..old"
    folder.mkdir()
    (folder / "x.py").write_text("x = 1\n")
    repo = history.add_repo(Target("folder", str(folder)))
    result = scan_repo(repo["id"])
    assert history.latest_scan_id(repo["id"]) == result.scan_id and results.latest(repo["id"]) == result


def test_rejects_bad_inputs(tmp_path):
    with pytest.raises(ValueError):
        history.add_repo(Target("folder", str(tmp_path / "missing")))
    with pytest.raises(ValueError):
        results.load("../etc", "0123456789ab")                   # API 값이 경로가 되는 곳
    with pytest.raises(ValueError):
        results.load("repo", "../../x")
    with pytest.raises(KeyError):
        scan_repo("not-connected")


def test_scan_lock_blocks_other_processes():
    """서버 작업 큐와 서버 없는 hook이 동시에 쓰지 않는다."""
    probe = "from wescope.store.lock import scan_lock\nwith scan_lock(timeout=0.3): pass"
    with scan_lock():
        busy = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    free = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert busy.returncode != 0 and "TimeoutError" in busy.stderr
    assert free.returncode == 0
