"""~/.wescope/results/<repo-id>/<scan-id>.json — 결과 원본. 보고서는 내려받을 때 이 JSON으로 만든다."""
import os
import re
import shutil
from pathlib import Path

from wescope.models.scan_result import ScanResult
from wescope.paths import home
from wescope.store import history

_REPO_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")   # Target.repo_id가 만드는 문자와 같다 (점·구분자 없음)
_SCAN_ID = re.compile(r"[0-9a-f]{12}")


def _dir(repo_id: str) -> Path:
    if not _REPO_ID.fullmatch(repo_id):   # API에서 온 값이 경로가 되므로 여기서 막는다
        raise ValueError("잘못된 저장소 id")
    return home() / "results" / repo_id


def save(result: ScanResult) -> Path:
    path = _dir(result.repo) / f"{result.scan_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(result.to_json(), encoding="utf-8")
    os.replace(temp, path)     # 쓰다가 멈춰도 반쯤 쓴 결과 파일이 남지 않게
    return path


def load(repo_id: str, scan_id: str) -> ScanResult | None:
    if not _SCAN_ID.fullmatch(scan_id):
        raise ValueError("잘못된 검사 id")
    path = _dir(repo_id) / f"{scan_id}.json"
    return ScanResult.from_json(path.read_text(encoding="utf-8")) if path.is_file() else None


def latest(repo_id: str) -> ScanResult | None:
    scan_id = history.latest_scan_id(repo_id)
    return load(repo_id, scan_id) if scan_id else None


def purge(repo_id: str):
    shutil.rmtree(_dir(repo_id), ignore_errors=True)
