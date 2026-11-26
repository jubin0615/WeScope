"""작업 큐: 한 번에 작업 1개 (검사 또는 수정안 만들기). 같은 작업이 기다리는 중이면 새로 만들지 않고 그 작업을
돌려준다(디바운스): 검사는 저장소마다, 수정안은 (저장소, 규칙)마다 하나.

대기 중인 검사는 실행될 때의 현재 파일을 검사하므로, 연속 요청을 하나로 합쳐도 마지막 상태를 검사하게 된다.
수정안 작업은 기존 검사의 scan_id를 그대로 쓴다 (진행은 같은 /api/scans/{scan_id}/events로 본다).
"""
import threading
from dataclasses import asdict, dataclass

from wescope.engine.aggregate import new_scan_id
from wescope.scan import fix_group, scan_repo


@dataclass
class Job:
    scan_id: str
    repo_id: str
    trigger: str
    status: str = "queued"            # queued / running / done / failed
    stage: str | None = None          # collect / analyze / organize / ai / save
    error: str | None = None
    summary: dict | None = None
    rule_id: str | None = None        # 수정안 작업이면 그 묶음의 규칙
    ai_progress: dict | None = None   # stage == "ai"일 때 {"done", "total"} (수정안 n/m)
    retry: bool = False               # [다른 수정안]
    version: int = 0                  # 바뀔 때마다 1 증가 (SSE가 변화를 알아챈다)

    def view(self) -> dict:
        data = asdict(self)
        del data["version"], data["retry"]
        return data


class Jobs:
    def __init__(self, run=scan_repo, fix=fix_group):
        self._run = run
        self._fix = fix
        self._lock = threading.Lock()            # 큐(pending·stopping)
        self._state = threading.Lock()           # 작업 상태 필드
        self._wake = threading.Event()
        self._pending: dict[tuple, Job] = {}   # (repo_id, rule_id) → 기다리는 작업. 검사는 rule_id가 None
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

    def submit(self, repo_id: str, trigger: str = "manual", *, rule_id: str | None = None, scan_id: str | None = None,
               retry: bool = False) -> Job:
        with self._lock:
            job = self._pending.get((repo_id, rule_id))
            if job is None:
                job = Job(scan_id or new_scan_id(), repo_id, trigger, rule_id=rule_id, retry=retry)
                self._pending[(repo_id, rule_id)] = self._jobs[job.scan_id] = job
            self._wake.set()
        return job

    def get(self, scan_id: str) -> Job | None:
        return self._jobs.get(scan_id)

    def busy(self, repo_id: str) -> bool:
        return any(key[0] == repo_id for key in self._pending) or             (self.current is not None and self.current.repo_id == repo_id)

    def snapshot(self, job: Job) -> tuple[int, dict]:
        """(version, 상태 사본). 작업 스레드가 여러 필드를 바꾸는 도중의 반쯤 바뀐 상태를 읽지 않게 잠금 안에서 읽는다."""
        with self._state:
            return job.version, job.view()

    def _update(self, job: Job, **changes):
        with self._state:
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
            def progress(stage, **detail):
                self._update(job, stage=stage, ai_progress=detail or None)
            try:
                if job.rule_id:
                    result = self._fix(job.repo_id, job.scan_id, job.rule_id, retry=job.retry, progress=progress)
                else:
                    result = self._run(job.repo_id, trigger=job.trigger, scan_id=job.scan_id, progress=progress)
                self._update(job, status="done", summary=result.summary)
            except Exception as error:   # 작업 하나가 실패해도 큐는 계속 돈다
                self._update(job, status="failed", error=str(error) or type(error).__name__)
            finally:
                self.current = None
