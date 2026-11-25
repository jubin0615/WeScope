"""~/.wescope/server.json — 실행 중인 서버의 포트·PID·접속 티켓. 중복 실행 감지와 hook이 서버를 찾는 데 쓴다."""
import json
import os
import socket
import urllib.request
from dataclasses import asdict, dataclass

from wescope.paths import home

COOKIE = "wescope_ticket"   # 접속 티켓을 담는 쿠키. hook도 이 이름으로 티켓을 보낸다


@dataclass
class Running:
    port: int
    pid: int
    ticket: str

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?ticket={self.ticket}"

    def alive(self) -> bool:
        """그 포트에서 We-Scope가, 같은 PID로 응답하는가 (PID만 보면 재사용된 다른 프로세스를 오인한다)."""
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=1) as resp:
                info = json.load(resp)
            return info.get("app") == "wescope" and info.get("pid") == self.pid
        except (OSError, ValueError):
            return False


def _path():
    return home() / "server.json"


def read() -> Running | None:
    try:
        return Running(**json.loads(_path().read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return None


def write(running: Running):
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # 티켓이 들어 있으므로 처음부터 소유자만 읽게 만든다 (Windows는 사용자 홈 폴더 권한에 맡긴다)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(asdict(running), f)


def clear(pid: int):
    """내가 쓴 server.json일 때만 지운다 (그사이 다른 서버가 쓴 파일은 남긴다)."""
    current = read()
    if current is None or current.pid == pid:
        _path().unlink(missing_ok=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
