"""커밋 자동 검사: hook 설치·해제(기존 hook 보존), 서버 있음/없음, 연속 커밋 디바운스, 실제 git commit."""
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from conftest import git
from wescope import hook
from wescope.collector.snapshot import Target
from wescope.paths import home
from wescope.server import state
from wescope.server.app import create_app
from wescope.store import history


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """커밋 하나 있는 Git 저장소를 연결해 둔다. 이 프로세스 안 검사는 Semgrep을 끈다."""
    monkeypatch.setattr("wescope.analyzers.semgrep.find_semgrep", lambda: None)
    root = tmp_path / "app"
    root.mkdir()
    (root / "app.py").write_text("print('hi')\n", encoding="utf-8")
    git(root, "init", "-q")
    commit(root, "first")
    return history.add_repo(Target("folder", str(root)))


def commit(root, message):
    (root / "log.txt").write_text(message, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", message)


def hook_scans(repo_id):
    return [s for s in history.scans(repo_id) if s["trigger"] == "hook"]


def wait_for(check, timeout):
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, "시간 안에 끝나지 않음"
        time.sleep(0.2)


@pytest.fixture
def live_server():
    """실제 포트에 서버를 띄우고 server.json을 쓴다 (hook이 찾는 방식 그대로)."""
    me = state.Running(port=state.free_port(), pid=os.getpid(), ticket="t" * 43)
    server = uvicorn.Server(uvicorn.Config(create_app(me.ticket, me.port), host="127.0.0.1", port=me.port,
                                           log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    wait_for(me.alive, 10)
    state.write(me)
    yield me
    server.should_exit = True
    thread.join(30)
    state.clear(me.pid)


def test_install_keeps_existing_hook_and_uninstall_removes_only_ours(repo):
    path = hook.hook_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/bash\necho mine\nexit 0\n", encoding="utf-8")
    other = {**repo, "id": "other-123"}   # 같은 Git 저장소의 다른 하위 폴더 연결
    hook.install(repo)
    hook.install(repo)                    # 두 번 켜도 한 줄
    hook.install(other)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "#!/bin/bash" and lines[-2:] == ["echo mine", "exit 0"]   # 우리 줄은 exit 앞(shebang 다음)
    assert sum(f"wescope-hook {repo['id']}" in line for line in lines) == 1
    assert hook.installed(repo) and hook.installed(other)
    hook.uninstall(repo)
    assert not hook.installed(repo) and hook.installed(other)
    hook.uninstall(other)
    assert path.read_text(encoding="utf-8") == "#!/bin/bash\necho mine\nexit 0\n"


def test_new_hook_file_is_removed_on_uninstall_and_non_shell_hook_is_refused(repo, tmp_path):
    path = hook.hook_path(repo)
    hook.install(repo)
    assert path.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
    hook.uninstall(repo)
    assert not path.exists()
    path.write_text("#!/usr/bin/env python\nprint('x')\n", encoding="utf-8")
    with pytest.raises(ValueError):
        hook.install(repo)
    assert hook.installed({"kind": "github", "location": "https://github.com/o/r", "id": "x"}) is None
    plain = tmp_path / "plain"
    plain.mkdir()
    assert hook.installed({"kind": "folder", "location": str(plain), "id": "x"}) is None


def test_without_server_scans_directly(repo, monkeypatch):
    monkeypatch.setattr(hook, "DEBOUNCE", 0)
    hook.run(repo["id"], "abc")
    assert len(hook_scans(repo["id"])) == 1
    hook.run("not-connected", "abc")      # 연결 해제한 저장소에 남은 hook은 아무것도 하지 않는다


def test_rapid_commits_scan_once(repo, monkeypatch):
    monkeypatch.setattr(hook, "DEBOUNCE", 1.0)
    first = threading.Thread(target=hook.run, args=(repo["id"], "aaa"))
    first.start()
    time.sleep(0.3)
    hook.run(repo["id"], "bbb")
    first.join()
    assert len(hook_scans(repo["id"])) == 1


def test_with_server_goes_through_job_queue(repo, live_server, monkeypatch):
    monkeypatch.setattr(hook, "DEBOUNCE", 60)   # 서버로 가지 않고 직접 검사하면 이 테스트가 멈춘다
    hook.run(repo["id"], "abc")
    wait_for(lambda: hook_scans(repo["id"]), 60)
    assert not (home() / f"hook-{repo['id']}.last").exists()


def test_real_git_commit_triggers_background_scan(repo, live_server):
    """Git(Windows면 Git for Windows의 sh)이 실제로 hook을 돌린다. 하위 프로세스라 Semgrep까지 돌아 느리다."""
    root = repo["location"]
    hook.install(repo)
    started = time.monotonic()
    commit(Path(root), "with server")
    assert time.monotonic() - started < 5          # 커밋은 검사를 기다리지 않는다
    wait_for(lambda: len(hook_scans(repo["id"])) == 1, 120)

    state.clear(live_server.pid)                    # 서버가 없는 것처럼: hook이 직접 검사한다
    commit(Path(root), "without server")
    wait_for(lambda: len(hook_scans(repo["id"])) == 2, 180)
    latest = history.scans(repo["id"])[0]
    assert latest["commit_sha"] == subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                                                  text=True).stdout.strip()


def test_hooks_path_inside_work_tree_is_not_touched(repo):
    """husky(core.hooksPath=.husky)처럼 hook이 커밋되는 폴더에 있으면 설치하지 않는다 (내 PC 경로가 팀 저장소로 퍼짐)."""
    root = Path(repo["location"])
    git(root, "config", "core.hooksPath", ".husky")
    assert hook.installed(repo) is None
    with pytest.raises(ValueError):
        hook.install(repo)
    assert not (root / ".husky").exists()


def test_stale_python_path_shows_off_and_reinstall_replaces_it(repo):
    path = hook.hook_path(repo)
    hook.install(repo)
    current = path.read_text(encoding="utf-8")
    path.write_text(current.replace(Path(sys.executable).as_posix(), "C:/old/python.exe"), encoding="utf-8")
    assert hook.installed(repo) is False             # 옛 경로 줄은 조용히 실패하므로 꺼짐으로 보인다
    hook.install(repo)
    assert path.read_text(encoding="utf-8") == current and hook.installed(repo)
