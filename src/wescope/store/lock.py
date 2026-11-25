"""~/.wescope/*.lock — 프로세스 간 잠금.

- scan.lock: 서버 작업 큐와 서버 없이 도는 hook이 같은 이력에 동시에 쓰지 않게
- launch.lock: 동시에 실행한 wescope끼리 '실행 중인 서버 확인 → 새 서버 시작'을 한 번에 하나씩
"""
import os
import threading
import time
from contextlib import contextmanager

from wescope.paths import home

if os.name == "nt":
    import msvcrt

    def _try(fd):
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd):
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _try(fd):
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)


class FileLock:
    """다른 스레드에서 풀 수 있고, 여러 번 풀어도 된다 (실행기가 '서버가 응답하면' 다른 스레드에서 푼다)."""

    def __init__(self, name: str):
        self._path = home() / name
        self._fd = None
        self._guard = threading.Lock()

    def acquire(self, timeout: float):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT)
        deadline = time.monotonic() + timeout
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                _try(fd)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise TimeoutError(f"다른 We-Scope 작업이 끝나지 않았어요 ({self._path.name})") from None
                time.sleep(0.1)
        self._fd = fd

    def release(self):
        with self._guard:
            fd, self._fd = self._fd, None
        if fd is not None:
            _unlock(fd)
            os.close(fd)


@contextmanager
def scan_lock(timeout: float = 600):
    lock = FileLock("scan.lock")
    lock.acquire(timeout)
    try:
        yield
    finally:
        lock.release()
