"""`wescope` 명령: 로컬 대시보드 서버를 띄우고 브라우저를 연다. 인자도 서브커맨드도 없다."""
import os
import secrets
import signal
import threading
import time
import webbrowser

import uvicorn

from wescope.server import state
from wescope.server.app import create_app
from wescope.store.lock import FileLock


def main() -> None:
    # '실행 중인 서버 확인 → 새 서버 시작'을 잠금 안에서 한다. 잠금은 새 서버가 실제로 응답한 뒤에 푼다.
    # (잠금이 없으면 동시에 실행했을 때, 또는 첫 서버가 아직 뜨는 중일 때 서버가 둘 뜨고 서로의 쿠키를 덮어쓴다)
    launch = FileLock("launch.lock")
    launch.acquire(timeout=60)
    try:
        running = state.read()
        if running and running.alive():
            print(f"We-Scope가 이미 실행 중이에요: {running.url}")
            webbrowser.open(running.url)
            return
        me = state.Running(port=state.free_port(), pid=os.getpid(), ticket=secrets.token_urlsafe(32))
        state.write(me)
        print(f"We-Scope 대시보드: {me.url}\n종료하려면 Ctrl+C를 누르세요.")
        threading.Thread(target=_open_when_ready, args=(me, launch), daemon=True).start()
        _serve(me)
    finally:
        launch.release()   # 서버가 끝내 뜨지 못한 경우에도 다음 실행이 기다리지 않게


def _open_when_ready(me: state.Running, launch: FileLock, timeout: float = 30):
    deadline = time.monotonic() + timeout
    while not me.alive():
        if time.monotonic() > deadline:
            return
        time.sleep(0.1)
    launch.release()
    webbrowser.open(me.url)   # 열지 못해도 주소는 터미널에 찍혀 있다


def _serve(me: state.Running):
    if hasattr(signal, "SIGBREAK"):
        # Windows: Ctrl+Break·터미널 창 닫기도 Ctrl+C처럼 끝낸다. uvicorn은 정리를 마친 뒤 신호를 다시 올리는데,
        # 기본 동작이면 그 자리에서 프로세스가 끝나 아래 finally(server.json 삭제)가 실행되지 않는다.
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    try:
        uvicorn.run(create_app(me.ticket, me.port), host="127.0.0.1", port=me.port, log_level="warning")
    except KeyboardInterrupt:
        pass
    finally:
        state.clear(me.pid)
    print("We-Scope를 종료했어요.")


if __name__ == "__main__":
    main()
