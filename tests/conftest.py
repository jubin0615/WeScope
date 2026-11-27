"""fixture 저장소를 임시 폴더로 옮겨 검사하는 헬퍼.

비밀값 표본은 파일에 `{{FAKE:종류}}`로 적어 두고 복사할 때 가짜 값으로 바꾼다. 실제 형식의 키를 저장소에 커밋하지 않기 위해서다
(GitHub push protection에 걸리고, 이 저장소 자체가 We-Scope 검사에서 비밀값 노출로 잡힌다).
"""
import base64
import json
import random
import re
import shutil
import string
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
_MARKER = re.compile(r"\{\{FAKE:(\w+?)(\d*)\}\}")
_EXPECT = re.compile(r"(?:#|//|<!--)\s*expect:\s*([\w-]+(?:\s*,\s*[\w-]+)*)")


def fake_secret(kind: str, seed: str) -> str:
    rng = random.Random(f"{kind}{seed}")

    def chars(n, alphabet=string.ascii_letters + string.digits):
        return "".join(rng.choice(alphabet) for _ in range(n))

    if kind == "service_role":
        part = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part({'iss': 'supabase', 'role': 'service_role'})}.{chars(43)}"
    return {
        "openai": "sk-proj-Wq" + chars(40),
        "stripe": "sk_live_" + chars(24),
        "github": "ghp_" + chars(36),
        "aws": "AKIA" + chars(16, string.ascii_uppercase + string.digits),
        "npm": "npm_" + chars(36),
        "password": "Pw" + chars(14),
        "pem": "MIIE" + chars(60, string.ascii_letters + string.digits + "+/"),   # PEM 개인키 본문 한 줄
    }[kind]


def materialize(name: str, dest: Path) -> tuple[Path, set[str]]:
    """fixture를 dest로 복사하고 표식을 가짜 비밀값으로 바꾼다. (경로, 심은 비밀값들)"""
    root = dest / name
    shutil.copytree(FIXTURES / name, root)
    planted = set()
    for path in root.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if "{{FAKE:" in text:
                def swap(m):
                    value = fake_secret(m[1], m[2])
                    planted.add(value)
                    return value
                path.write_text(_MARKER.sub(swap, text), encoding="utf-8")
    return root, planted


def git(root: Path, *args: str):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def make_git_repo(root: Path, commit: list[str] | None = None):
    """root를 Git 저장소로 만들고 commit 목록(없으면 전부)을 커밋한다."""
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "test@wescope.local")
    git(root, "config", "user.name", "We-Scope Test")
    git(root, "config", "core.autocrlf", "false")
    git(root, "add", "-f", *(commit or ["."]))
    git(root, "commit", "-q", "-m", "fixture")


def expected_hits(root: Path, file_level: list[str] = ()) -> set[tuple[str, str, int]]:
    """'# expect: rule-a, rule-b' 주석 다음 줄에 그 규칙이 잡혀야 한다. file_level은 'rule_id 경로'(줄 0)."""
    expected = {(line.split()[0], line.split()[1], 0) for line in file_level}
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(root).as_posix()
        for number, line in enumerate(lines, 1):
            if m := _EXPECT.search(line):
                for rule in m[1].split(","):
                    if rule.strip():
                        expected.add((rule.strip(), rel, number + 1))
    return expected


@pytest.fixture(autouse=True)
def wescope_home(tmp_path, monkeypatch):
    monkeypatch.setenv("WESCOPE_HOME", str(tmp_path / "home"))
