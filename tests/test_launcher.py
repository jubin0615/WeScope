import os
import signal
import subprocess
import sys
import threading
import time

import uvicorn

from wescope import __main__ as launcher
from wescope.server import state
from wescope.server.app import create_app


def serve(port):
    server = uvicorn.Server(uvicorn.Config(create_app("t" * 43, port), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    return server, thread


def test_server_json_round_trip_and_owner_only_clear():
    assert state.read() is None
    state.write(state.Running(1234, 42, "secret"))
    assert state.read() == state.Running(1234, 42, "secret")
    assert state.read().url == "http://127.0.0.1:1234/?ticket=secret"
    state.clear(pid=7)                 # 다른 서버가 쓴 파일은 지우지 않는다
    assert state.read() is not None
    state.clear(pid=42)
    assert state.read() is None


def test_alive_checks_port_and_pid():
    port = state.free_port()
    server, thread = serve(port)
    try:
        assert state.Running(port, os.getpid(), "x").alive()
        assert not state.Running(port, os.getpid() + 1, "x").alive()      # PID가 다르면 다른 서버
    finally:
        server.should_exit = True
        thread.join()
    assert not state.Running(port, os.getpid(), "x").alive()              # 꺼진 서버


def test_second_launch_reopens_browser_instead_of_starting(monkeypatch):
    port = state.free_port()
    server, thread = serve(port)
    opened, started = [], []
    monkeypatch.setattr(launcher.webbrowser, "open", opened.append)
    monkeypatch.setattr(launcher.uvicorn, "run", lambda *a, **k: started.append(1))
    try:
        state.write(state.Running(port, os.getpid(), "abc"))
        launcher.main()
        assert opened == [f"http://127.0.0.1:{port}/?ticket=abc"] and started == []
    finally:
        server.should_exit = True
        thread.join()


def test_stale_server_json_is_replaced(monkeypatch):
    state.write(state.Running(state.free_port(), 999999, "old"))           # 비정상 종료로 남은 파일
    started = []
    monkeypatch.setattr(launcher, "_open_when_ready", lambda *a: None)
    monkeypatch.setattr(launcher.uvicorn, "run", lambda app, host, port, **k: started.append((host, port, state.read())))
    launcher.main()
    host, port, during = started[0]
    assert host == "127.0.0.1" and during.pid == os.getpid() and during.ticket != "old"
    assert state.read() is None                                           # 종료하면 server.json을 지운다


def test_simultaneous_launches_start_one_server(tmp_path):
    """PR #2 리뷰: wescope를 동시에 두 번 실행하면 서버가 둘 뜨던 문제 (잠금 전에는 4번 중 2번 재현)."""
    env = {**os.environ, "WESCOPE_HOME": str(tmp_path / "home"), "PYTHONIOENCODING": "utf-8"}
    code = "import webbrowser; webbrowser.open = lambda *a, **k: True\nfrom wescope.__main__ import main; main()"
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    procs = [subprocess.Popen([sys.executable, "-c", code], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", creationflags=flags) for _ in range(3)]
    try:
        deadline = time.monotonic() + 60
        while sum(p.poll() is None for p in procs) > 1 and time.monotonic() < deadline:
            time.sleep(0.2)
        servers = [p for p in procs if p.poll() is None]
        assert len(servers) == 1
        assert state.read() is not None and state.read().alive()
    finally:
        for p in procs:
            if p.poll() is None:
                p.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
        outputs = [p.communicate(timeout=30)[0] for p in procs]
    assert sum("이미 실행 중" in out for out in outputs) == 2
    assert len({line.split("ticket=")[1] for out in outputs for line in out.splitlines() if "ticket=" in line}) == 1
