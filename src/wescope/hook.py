"""커밋 자동 검사: post-commit hook 설치·해제와 hook이 부르는 내부 진입점 (ARCHITECTURE §1-2).

hook 줄:  '<python>' -m wescope.hook --repo <id> --commit "$(git rev-parse HEAD)" >/dev/null 2>&1 & # wescope-hook <id>
- 백그라운드(&)라 커밋을 느리게 하지 않고, 출력이 없어 사용자에게 아무것도 보이지 않는다.
- 서버가 살아 있으면 서버 작업 큐에 맡기고, 없으면 디바운스 뒤 scan.lock을 잡고 직접 검사한다 (ChatGPT 없음).
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from wescope.collector.snapshot import git
from wescope.paths import home
from wescope.scan import scan_repo
from wescope.server import state
from wescope.store import history
from wescope.store.lock import scan_lock

DEBOUNCE = 3.0                                       # 연속 커밋은 마지막 것만 검사한다 (서버 없을 때)
_SHELL = re.compile(r"#!.*\b(?:ba|da|z|k)?sh\b")     # 셸 스크립트 hook에만 줄을 넣을 수 있다
UNSUPPORTED = "자동 검사는 로컬 Git 폴더 프로젝트에서만 쓸 수 있어요 (husky처럼 hook을 저장소 안 폴더에 두는 프로젝트 제외)"


def _marker(repo_id: str) -> str:
    return f"# wescope-hook {repo_id}"


def _line(repo_id: str) -> str:
    python = Path(sys.executable).as_posix().replace("'", "'\\''")   # Git for Windows sh에서 역슬래시 문제 없게 / 로
    return (f"'{python}' -m wescope.hook --repo {repo_id} --commit \"$(git rev-parse HEAD)\" "
            f">/dev/null 2>&1 & {_marker(repo_id)}")


def hook_path(repo: dict) -> Path | None:
    """이 저장소의 post-commit 파일 (worktree는 git이 맞춰 준다). 로컬 Git 폴더가 아니면 None.
    core.hooksPath가 .git 밖(husky의 .husky/ 등)을 가리켜도 None: 그 파일은 커밋되어 내 PC 경로가 팀 저장소로 퍼질 수 있다."""
    if repo["kind"] != "folder":
        return None
    try:
        path, common = git("rev-parse", "--path-format=absolute", "--git-path", "hooks/post-commit",
                           "--git-common-dir", cwd=Path(repo["location"])).splitlines()
    except (subprocess.CalledProcessError, OSError, ValueError):
        return None
    return Path(path) if Path(common).resolve() in Path(path).resolve().parents else None


def installed(repo: dict) -> bool | None:
    """지금 Python 경로로 된 줄이 있을 때만 켜짐. We-Scope를 다른 Python으로 다시 설치해 옛 경로만 남았으면 꺼짐으로 보인다
    (그 줄은 조용히 실패하므로). 다시 켜면 install()이 새 경로로 바꾼다."""
    path = hook_path(repo)
    if path is None:
        return None
    return path.is_file() and _line(repo["id"]) in path.read_text(encoding="utf-8", errors="replace").splitlines()


def install(repo: dict):
    """기존 hook은 그대로 두고 shebang 바로 다음 줄에 넣는다 (끝에 덧붙이면 기존 hook의 exit 뒤라 실행되지 않을 수 있다)."""
    path = hook_path(repo)
    if path is None:
        raise ValueError(UNSUPPORTED)
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else ["#!/bin/sh"]
    if _line(repo["id"]) in lines:
        return
    lines = [line for line in lines if _marker(repo["id"]) not in line]   # 옛 Python 경로로 된 우리 줄
    if not lines or not _SHELL.match(lines[0]):
        raise ValueError("기존 post-commit hook이 셸 스크립트가 아니라 자동 검사를 넣을 수 없어요")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join([lines[0], _line(repo["id"]), *lines[1:]]) + "\n", encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | 0o111)


def uninstall(repo: dict):
    """우리 줄만 지운다. 남은 것이 shebang뿐이면(우리가 만든 파일) 파일을 지운다."""
    path = hook_path(repo)
    if path is None or not path.is_file():
        return
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if _marker(repo["id"]) not in line]
    if [line for line in lines if line.strip()] in ([], ["#!/bin/sh"]):
        path.unlink()
    else:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def run(repo_id: str, commit: str):
    if history.get_repo(repo_id) is None:
        return                                   # 연결을 해제한 저장소에 남은 hook
    server = state.read()
    if server and server.alive() and _trigger(server, repo_id):
        return                                   # 디바운스는 서버 큐가 한다 (저장소마다 대기 작업 하나)
    last = home() / f"hook-{repo_id}.last"
    last.write_text(commit, encoding="utf-8")
    time.sleep(DEBOUNCE)
    with scan_lock():
        pass                                     # 돌고 있는 검사가 끝날 때까지 기다린다
    if last.read_text(encoding="utf-8") != commit:
        return                                   # 더 새 커밋의 hook이 검사한다 (현재 파일 기준이라 결과가 같다)
    scan_repo(repo_id, trigger="hook")


def _trigger(server: state.Running, repo_id: str) -> bool:
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.port}/api/hook-trigger", method="POST",
        data=json.dumps({"repo_id": repo_id}).encode(),
        headers={"Content-Type": "application/json", "Cookie": f"{state.COOKIE}={server.ticket}"})
    try:
        with urllib.request.urlopen(request, timeout=5):
            return True
    except OSError:
        return False                             # 서버가 막 꺼지는 중이면 직접 검사한다


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m wescope.hook")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", default="")
    args = parser.parse_args(argv)
    try:
        run(args.repo, args.commit)
    except Exception:
        pass   # 커밋 뒤 백그라운드 작업이라 보여 줄 곳이 없다. 실패하면 다음 커밋이나 [다시 스캔]이 검사한다


if __name__ == "__main__":
    main()
