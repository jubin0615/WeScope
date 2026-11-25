"""`wescope` 명령: 로컬 대시보드 서버를 띄우고 브라우저를 연다. 인자도 서브커맨드도 없다."""
import os
import secrets
import signal
import threading
import webbrowser

import uvicorn

from wescope.server import state
from wescope.server.app import create_app


def main() -> None:
    running = state.read()
    if running and running.alive():
        print(f"We-Scope가 이미 실행 중이에요: {running.url}")
        webbrowser.open(running.url)
        return
    me = state.Running(port=state.free_port(), pid=os.getpid(), ticket=secrets.token_urlsafe(32))
    state.write(me)
    print(f"We-Scope 대시보드: {me.url}\n종료하려면 Ctrl+C를 누르세요.")
    threading.Timer(0.8, webbrowser.open, args=[me.url]).start()   # 열지 못해도 주소는 위에 찍혀 있다
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
