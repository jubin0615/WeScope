"""스냅샷: 검사 대상을 임시 폴더로 옮긴다. 원본 폴더에는 아무것도 쓰지 않는다."""
import hashlib
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

import pathspec

from wescope.collector import sensitive
from wescope.paths import home

EXCLUDED_DIRS = {
    "node_modules", ".git", ".venv", "venv", "build", "dist", "coverage", "__pycache__", ".next",
    ".nuxt", ".output", "vendor", "target", ".gradle", ".tox", ".mypy_cache", ".pytest_cache",
}
MAX_BYTES = 5 * 1024 * 1024


@dataclass
class Target:
    kind: str                 # folder / github
    location: str             # 폴더 경로 또는 저장소 URL
    branch: str | None = None
    excludes: tuple[str, ...] = ()   # 대시보드 설정의 제외 패턴 (.wescopeignore와 같은 문법)

    @property
    def repo_id(self) -> str:
        """`읽기 쉬운 이름-위치 해시`. 이름만으로는 /app/one과 /app_one이 겹치므로 위치 전체의 해시를 붙인다.
        영문·숫자·_·-만 써서 그대로 폴더 이름이 된다 (store.results의 검사 규칙과 같다)."""
        name = re.sub(r"[^A-Za-z0-9]+", "_", self.location.rstrip("/\\").split("://")[-1]).strip("_")[-40:].strip("_")
        digest = hashlib.sha256(f"{self.kind}|{self.location}".encode()).hexdigest()[:12]
        return f"{name}-{digest}" if name else digest


@dataclass
class Snapshot:
    source: dict
    files: list[str]                    # Track A 후보: 복사된 파일 (텍스트 여부는 context가 판단)
    all_files: list[str]                # Track B: 바이너리·큰 파일·민감 파일 포함
    sensitive_files: list[dict]         # Track D: {path, kind, git}
    git_status: dict[str, str] | None   # committed / untracked / ignored, Git이 아니면 None
    skipped: dict[str, str]
    excluded: list[str]                 # 제외 패턴에 걸린 파일, 폴더는 '경로/' (비교 단계가 '해결'로 오인하지 않게)


def git(*args: str, cwd: Path | None = None) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)
    return done.stdout.decode("utf-8", "replace").strip()


def take(target: Target, dest: Path) -> Snapshot:
    if target.kind == "github":
        return _github(target, dest)
    src = Path(target.location)
    if not src.is_dir():
        raise FileNotFoundError(f"폴더를 찾을 수 없어요: {src}")
    status = _git_status(src)
    source = {"kind": "folder", "location": str(src), "git": status is not None}
    if status is not None:
        source["commit"] = _try_git("rev-parse", "HEAD", cwd=src)
        source["branch"] = _try_git("rev-parse", "--abbrev-ref", "HEAD", cwd=src)
    return _copy(src, dest, source, status, target.excludes)


def _github(target: Target, dest: Path) -> Snapshot:
    local = home() / "repos" / target.repo_id
    if not (local / ".git").exists():
        local.parent.mkdir(parents=True, exist_ok=True)
        git("clone", "--no-tags", "--", target.location, str(local))
    git("fetch", "--prune", "origin", cwd=local)
    branch = target.branch or git("symbolic-ref", "--short", "refs/remotes/origin/HEAD", cwd=local).split("/", 1)[1]
    commit = git("rev-parse", f"origin/{branch}^{{commit}}", cwd=local)
    staging = dest.parent / (dest.name + "-export")
    archive = dest.parent / (dest.name + ".tar")
    try:
        git("archive", "--format=tar", "-o", str(archive), commit, cwd=local)
        with tarfile.open(archive) as tar:
            tar.extractall(staging, filter="data")
        source = {"kind": "github", "location": target.location, "git": True, "commit": commit, "branch": branch}
        return _copy(staging, dest, source, None, target.excludes, all_committed=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        archive.unlink(missing_ok=True)


def _copy(src: Path, dest: Path, source: dict, status, excludes=(), all_committed=False) -> Snapshot:
    ignore_file = src / ".wescopeignore"
    # 뒤에 오는 패턴이 이긴다: 대시보드 설정을 뒤에 둬서 .wescopeignore의 !되살리기 줄이 설정을 무르지 못하게 한다
    lines = [*(ignore_file.read_text("utf-8").splitlines() if ignore_file.is_file() else []), *excludes]
    extra_ignore = pathspec.PathSpec.from_lines("gitwildmatch", lines) if lines else None
    files, all_files, sensitive_files, skipped, git_status, excluded = [], [], [], {}, {}, []
    for path in _walk(src, src, extra_ignore, skipped, excluded):
        rel = path.relative_to(src).as_posix()
        all_files.append(rel)
        state = "committed" if all_committed else (status(rel) if status else None)
        if state:
            git_status[rel] = state
        kind = sensitive.kind(rel)
        if kind:
            sensitive_files.append({"path": rel, "kind": kind, "git": state})
            continue
        if path.stat().st_size > MAX_BYTES:
            skipped[rel] = "5MB 초과"
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        files.append(rel)
    has_git = all_committed or status is not None
    return Snapshot(source, sorted(files), sorted(all_files), sorted(sensitive_files, key=lambda s: s["path"]),
                    git_status if has_git else None, skipped, excluded)


def _walk(root: Path, current: Path, extra_ignore, skipped, excluded):
    for entry in sorted(current.iterdir()):
        rel = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            skipped[rel] = "심볼릭 링크"
            continue
        if entry.is_dir():
            if entry.name in EXCLUDED_DIRS:
                continue
            if extra_ignore and extra_ignore.match_file(rel + "/"):
                excluded.append(rel + "/")
            else:
                yield from _walk(root, entry, extra_ignore, skipped, excluded)
        elif entry.is_file() and not entry.name.endswith(".min.js"):
            if extra_ignore and extra_ignore.match_file(rel):
                excluded.append(rel)
            else:
                yield entry


def _try_git(*args, cwd) -> str | None:
    try:
        return git(*args, cwd=cwd)
    except subprocess.CalledProcessError:
        return None   # 커밋이 하나도 없는 저장소


def _git_status(src: Path):
    """Git 폴더면 rel_path → committed/untracked/ignored 함수를, 아니면 None."""
    if _try_git("rev-parse", "--is-inside-work-tree", cwd=src) != "true":
        return None
    tracked = set(git("ls-files", "-z", cwd=src).split("\0"))
    ignored = [p for p in git("ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory",
                              cwd=src).split("\0") if p]

    def status(rel: str) -> str:
        if rel in tracked:
            return "committed"
        if any(rel == p or (p.endswith("/") and rel.startswith(p)) for p in ignored):
            return "ignored"
        return "untracked"
    return status
