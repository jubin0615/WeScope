"""작업 큐: 한 번에 스캔 1개. 같은 저장소의 요청이 기다리는 중이면 새로 만들지 않고 그 작업을 돌려준다(디바운스).

대기 중인 작업은 실행될 때의 현재 파일을 검사하므로, 연속 요청을 하나로 합쳐도 마지막 상태를 검사하게 된다.
"""
import threading
from dataclasses import asdict, dataclass

from wescope.engine.aggregate import new_scan_id
from wescope.scan import scan_repo


@dataclass
class Job:
    scan_id: str
    repo_id: str
    trigger: str
    status: str = "queued"            # queued / running / done / failed
    stage: str | None = None          # collect / analyze / organize / save
    error: str | None = None
    summary: dict | None = None
    version: int = 0                  # 바뀔 때마다 1 증가 (SSE가 변화를 알아챈다)

    def view(self) -> dict:
        data = asdict(self)
        del data["version"]
        return data


class Jobs:
    def __init__(self, run=scan_repo):
        self._run = run
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._pending: dict[str, Job] = {}     # repo_id → 기다리는 작업 (저장소마다 하나)
        self._jobs: dict[str, Job] = {}        # scan_id → 작업. shortcut: 서버가 떠 있는 동안 계속 쌓인다 (수백 개 수준)
        self._stopping = False
        # daemon: 정상 종료는 stop()이 스캔을 마칠 때까지 기다리고, 비정상 종료 때는 프로세스 종료를 막지 않는다
        self._thread = threading.Thread(target=self._worker, name="wescope-jobs", daemon=True)
        self.current: Job | None = None

    def start(self):
        self._thread.start()

    def stop(self):
        """새 작업은 받지 않고, 돌고 있는 스캔은 끝까지 마친다 (임시 폴더 정리·저장이 중간에 끊기지 않게)."""
        with self._lock:
            self._stopping = True
            self._wake.set()
        if self._thread.is_alive():
            self._thread.join()

    def submit(self, repo_id: str, trigger: str = "manual") -> Job:
        with self._lock:
            job = self._pending.get(repo_id)
            if job is None:
                job = Job(new_scan_id(), repo_id, trigger)
                self._pending[repo_id] = self._jobs[job.scan_id] = job
            self._wake.set()
        return job

    def get(self, scan_id: str) -> Job | None:
        return self._jobs.get(scan_id)

    def busy(self, repo_id: str) -> bool:
        return repo_id in self._pending or (self.current is not None and self.current.repo_id == repo_id)

    def _update(self, job: Job, **changes):
        for key, value in changes.items():
            setattr(job, key, value)
        job.version += 1

    def _worker(self):
        while True:
            self._wake.wait()
            with self._lock:
                if self._stopping:
                    return
                if not self._pending:
                    self._wake.clear()
                    continue
                job = self._pending.pop(next(iter(self._pending)))
                self.current = job
            self._update(job, status="running")
            try:
                result = self._run(job.repo_id, trigger=job.trigger, scan_id=job.scan_id,
                                   progress=lambda stage: self._update(job, stage=stage))
                self._update(job, status="done", summary=result.summary)
            except Exception as error:   # 작업 하나가 실패해도 큐는 계속 돈다
                self._update(job, status="failed", error=str(error) or type(error).__name__)
            finally:
                self.current = None
