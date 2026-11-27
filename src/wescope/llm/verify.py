"""수정안 로컬 검증 (AI.md §3-4): 스냅샷 사본에 적용 → 문법 → 같은 탐지기로 재검사.

사용자 폴더는 건드리지 않는다. 스냅샷(이미 임시 폴더)을 한 번 더 복사해 그 위에서만 적용한다.
재검사 함수는 scan.py가 넘긴다 (llm은 analyzers를 import하지 않는다).
"""
import ast
import shutil
import subprocess
import tempfile
from pathlib import Path

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser

from wescope.llm.guards import UNSUPPORTED, diff_files, safe_path, with_git_headers

_GRAMMARS = {".js": tree_sitter_javascript.language, ".jsx": tree_sitter_javascript.language,
             ".mjs": tree_sitter_javascript.language, ".cjs": tree_sitter_javascript.language,
             ".ts": tree_sitter_typescript.language_typescript, ".tsx": tree_sitter_typescript.language_tsx}


def syntax_error(path: Path) -> str | None:
    """문법 오류 설명, 없으면 None. 검사할 수 없는 언어도 None."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".py":
        try:
            ast.parse(text)
        except SyntaxError as error:
            return f"{error.lineno}번째 줄 근처"
        return None
    grammar = _GRAMMARS.get(path.suffix)
    if grammar is None:
        return None
    root = Parser(Language(grammar())).parse(text.encode("utf-8")).root_node
    if not root.has_error:
        return None
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            return f"{node.start_point[0] + 1}번째 줄 근처"
        stack.extend(reversed(node.children))
    return "구문을 해석하지 못했어요"


def verify(root: Path, diff: str, redactor, group, before, rescan) -> dict:
    """→ {"status": verified|partial|failed, "apply", "syntax", "rescan", "reasons": [...]}.
    group: 고치려는 발견들, before: 이번 검사의 전체 발견,
    rescan(folder) → (그 폴더의 발견 목록, 원래 검사에서는 끝났는데 이번엔 끝까지 못 돈 탐지기 id 목록)."""
    checks = {"status": "failed", "apply": False, "syntax": None, "rescan": None, "reasons": []}
    reasons = checks["reasons"]
    group_files = {f.location.file for f in group}
    changed, created, deleted = diff_files(diff)
    touched = changed | created
    if deleted or any(line.startswith(UNSUPPORTED) for line in diff.splitlines()):
        reasons.append("파일을 지우거나 이름·권한을 바꾸는 수정안은 받지 않아요")
        return checks
    if not touched:
        reasons.append("diff에서 바꾸는 파일을 찾지 못했어요 (unified diff 형식이 아님)")
        return checks
    outside = sorted(p for p in touched if not safe_path(p)) or sorted(changed - group_files)
    if outside:
        reasons.append("고칠 대상이 아닌 파일을 바꿨어요: " + ", ".join(outside))
        return checks

    with tempfile.TemporaryDirectory(prefix="wescope-fix-") as work:
        copy = Path(work) / "root"
        shutil.copytree(root, copy)
        for path in changed:
            file = copy / path
            if not file.is_file():
                reasons.append(f"없는 파일을 고치려고 했어요: {path}")
                return checks
            # 보낸 코드는 LF였다. Windows 체크아웃(CRLF)에 LF diff를 적용하면 실패하므로 사본만 LF로 맞춘다
            file.write_bytes(file.read_bytes().replace(b"\r\n", b"\n"))
        patch = Path(work) / "fix.diff"
        patch.write_text(with_git_headers(redactor.reveal(diff)), encoding="utf-8", newline="\n")
        done = subprocess.run(["git", "apply", "--recount", "--whitespace=nowarn", str(patch)], cwd=copy,
                              capture_output=True)
        if done.returncode:
            first = (done.stderr.decode("utf-8", "replace").strip().splitlines() or ["알 수 없는 오류"])[0]
            message = redactor.hide(first)   # git이 실패한 줄을 인용하면 복원한 비밀값이 들어 있을 수 있다
            reasons.append(f"diff를 적용하지 못했어요: {message}")
            return checks
        checks["apply"] = True

        errors = [f"{p}: 문법 오류 ({e})" for p in sorted(touched) if (e := syntax_error(copy / p))]
        checks["syntax"] = not errors
        if errors:
            reasons.extend(errors)
            return checks

        try:
            after, incomplete = rescan(copy)
        except Exception as error:   # 재검사가 안 되면 적용·문법까지만 확인된 것
            reasons.append(f"재검사를 하지 못했어요: {type(error).__name__}")
            checks["status"] = "partial"
            return checks

    rule = group[0].rule_id
    ours = {f.fingerprint for f in group}
    others = {f.fingerprint for f in before if f.rule_id == rule} - ours        # 오탐 표시 등으로 그룹에서 뺀 것
    # 새로 만든 파일도 본다: 문제를 다른 파일로 옮기기만 한 수정안은 고친 게 아니다
    remaining = [f for f in after if f.rule_id == rule and f.location.file in group_files | touched
                 and f.fingerprint not in others]
    known = {f.fingerprint for f in before}
    new = [f for f in after if f.location.file in touched and f.rule_id != rule and f.fingerprint not in known]
    reasons += [f"문제가 남아 있어요: {f.location.file}:{f.location.line}" for f in remaining]
    reasons += [f"새 위험 후보가 생겼어요: {f.rule_id} {f.location.file}:{f.location.line}" for f in new]
    if incomplete:     # 탐지기가 끝까지 못 돌았으면 "발견 없음"이 "고쳐짐"을 뜻하지 않는다
        reasons.append("재검사를 끝까지 하지 못했어요: " + ", ".join(incomplete))
    checks["rescan"] = not remaining and not new and not incomplete
    checks["status"] = "verified" if checks["rescan"] else "partial"
    if group[0].source == "ai":
        # 정적 재검사는 ChatGPT가 찾은 발견을 원래 못 찾으므로 '사라졌다'가 고쳤다는 뜻이 아니다 (AI.md §3-4).
        # 새 위험이 생겼는지는 위에서 그대로 봤다. 판정 불가(None)로 두고 partial
        reasons.insert(0, "정적 분석으로는 다시 확인할 수 없는 ChatGPT 발견이에요 (적용·문법만 확인했어요)")
        checks["rescan"], checks["status"] = None, "partial"
    return checks
