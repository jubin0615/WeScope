import hashlib
from pathlib import Path

from conftest import git, make_git_repo, materialize
from wescope.collector.context import collect
from wescope.collector.snapshot import Target
from wescope.scan import run_scan


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode() + path.read_bytes())
    return digest.hexdigest()


def test_scan_never_changes_the_original(tmp_path):
    """불변식: 검사 대상 폴더(.git 포함)는 스캔 전후가 같다."""
    root, _ = materialize("secrets_zoo", tmp_path)
    make_git_repo(root)
    before = tree_hash(root)
    run_scan(Target("folder", str(root)))
    assert tree_hash(root) == before


def test_sensitive_files_are_recorded_but_never_copied(tmp_path):
    root, _ = materialize("secrets_zoo", tmp_path)
    with collect(Target("folder", str(root))) as ctx:
        assert ".env" in ctx.all_files and ".env" not in ctx.files
        assert not (ctx.root / ".env").exists() and not (ctx.root / "serviceAccountKey.json").exists()
        assert (ctx.root / ".env.example").exists()          # 예시 파일은 일반 텍스트
        kinds = {s["path"]: (s["kind"], s["git"]) for s in ctx.sensitive_files}
        assert kinds[".env"] == ("env", None) and kinds["app.db"] == ("data", None)
    assert not ctx.root.exists()                              # 임시 스냅샷은 지워진다


def test_excluded_paths_and_limits(tmp_path):
    root = tmp_path / "app"
    for rel in ["node_modules/lib/index.js", ".venv/x.py", "dist/bundle.js", "static/app.min.js", "src/ok.py",
                "generated/out.py"]:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x = 1\n")
    (root / ".wescopeignore").write_text("generated/\n")
    (root / "big.txt").write_bytes(b"a" * (5 * 1024 * 1024 + 1))
    (root / "latin1.py").write_bytes("name = 'caf\xe9'\n".encode("latin-1"))
    with collect(Target("folder", str(root))) as ctx:
        assert "src/ok.py" in ctx.files
        assert not [f for f in ctx.all_files if f.startswith(("node_modules", ".venv", "dist", "generated"))]
        assert "static/app.min.js" not in ctx.all_files
        assert ctx.skipped["big.txt"] == "5MB 초과" and "big.txt" in ctx.all_files
        assert ctx.text("latin1.py") is None and ctx.skipped["latin1.py"] == "UTF-8이 아님"


def test_git_file_states(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text(".env\nlogs/\n")
    (root / "app.py").write_text("print(1)\n")
    make_git_repo(root)
    (root / ".env").write_text("A=1\n")
    (root / "new.py").write_text("print(2)\n")
    (root / "logs").mkdir()
    (root / "logs" / "a.txt").write_text("x\n")
    with collect(Target("folder", str(root))) as ctx:
        assert ctx.source["git"] and len(ctx.source["commit"]) == 40 and ctx.source["branch"] == "main"
        assert ctx.git_status["app.py"] == "committed"
        assert ctx.git_status["new.py"] == "untracked"
        assert ctx.git_status[".env"] == "ignored" and ctx.git_status["logs/a.txt"] == "ignored"


def test_github_target_scans_latest_commit(tmp_path):
    """GitHub 주소: We-Scope 전용 clone → 원격 최신 커밋만 검사 (네트워크 대신 로컬 bare 저장소 사용)."""
    work = tmp_path / "work"
    work.mkdir()
    (work / "app.py").write_text("print(1)\n")
    make_git_repo(work)
    remote = tmp_path / "remote.git"
    git(tmp_path, "clone", "-q", "--bare", str(work), str(remote))
    target = Target("github", remote.as_posix())
    with collect(target) as ctx:
        first = ctx.source["commit"]
        assert ctx.files == ["app.py"] and ctx.git_status == {"app.py": "committed"}
    (work / "second.py").write_text("print(2)\n")
    git(work, "add", "second.py")
    git(work, "commit", "-q", "-m", "second")
    git(work, "push", "-q", str(remote), "main")
    with collect(target) as ctx:                               # 두 번째는 fetch로 최신을 받는다
        assert ctx.source["commit"] != first and "second.py" in ctx.files
