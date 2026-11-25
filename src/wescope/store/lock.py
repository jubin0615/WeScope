"""~/.wescope/scan.lock — 서버 작업 큐와 서버 없이 도는 hook이 같은 이력에 동시에 쓰지 않게 하는 프로세스 간 잠금."""
import os
import time
from contextlib import contextmanager

from wescope.paths import home

if os.name == "nt":
    import msvcrt

    def _try(fd):
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _release(fd):
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _try(fd):
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _release(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def scan_lock(timeout: float = 600):
    path = home() / "scan.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                _try(fd)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("다른 검사가 끝나지 않았어요") from None
                time.sleep(0.1)
        try:
            yield
        finally:
            _release(fd)
    finally:
        os.close(fd)
