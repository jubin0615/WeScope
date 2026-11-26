"""입력·출력 가드 (AI.md §6).

- 보내기 전: 탐지된 비밀값을 «WS_SECRET_n»으로 바꾼다. 민감 파일(.env·키)은 스냅샷에 복사되지 않으므로 애초에 보낼 수 없다.
- 지시문 의심: 코드·주석에 모델에게 하는 말 같은 문장이나 보이지 않는 제어 문자가 있으면 표시한다.
- 받은 뒤: diff가 바꾸는 파일을 확인한다.
"""
import re

PLACEHOLDER = "«WS_SECRET_{}»"
_SUSPICIOUS = re.compile(
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions|disregard\s+.{0,30}instructions|system\s+prompt"
    r"|you\s+are\s+(chatgpt|an?\s+ai)|mark\s+(this|it)\s+as\s+(safe|false\s+positive)"
    r"|이전\s*지시|지시를?\s*무시|오탐으로\s*(처리|표시)|안전하다고\s*(판단|답)"
    r"|[​-‏‪-‮⁦-⁩]",
    re.I)


class Redactor:
    """비밀값 ↔ 자리표시. 번호는 값 순서로 정해서 같은 코드면 같은 요청(캐시 적중)이 된다."""

    def __init__(self, values: list[str]):
        self._pairs = [(value, PLACEHOLDER.format(n)) for n, value in enumerate(values, 1)]   # 긴 값부터 (registry.values)

    def hide(self, text: str) -> str:
        for value, placeholder in self._pairs:
            text = text.replace(value, placeholder)
        return text

    def reveal(self, text: str) -> str:
        """임시 사본에 적용할 때만 쓴다. 결과는 화면·저장·로그로 내보내지 않는다."""
        for value, placeholder in self._pairs:
            text = text.replace(placeholder, value)
        return text


def map_strings(value, fn):
    """JSON 같은 값 안의 모든 문자열에 fn을 적용한 사본."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: map_strings(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [map_strings(v, fn) for v in value]
    return value


def suspicious(text: str) -> bool:
    return bool(_SUSPICIOUS.search(text))


# 파일 삭제 말고도 이름·권한을 바꾸는 git 확장 머리줄. 이런 줄은 ---/+++ 없이도 파일을 바꾼다
UNSUPPORTED = ("deleted file mode", "rename from", "rename to", "copy from", "copy to", "old mode", "new mode",
               "similarity index", "dissimilarity index", "GIT binary patch", "Binary files")


def _headers(lines: list[str]):
    """(줄 번호, 옛 경로, 새 경로). 파일 머리줄은 '--- '·'+++ '·'@@' 세 줄이 이어진 곳이다
    (hunk 안에서 '-- x'를 지우고 '++ y'를 넣는 줄과 구분). 경로는 a/·b/ 접두어를 뗀 상대 경로."""
    for i in range(len(lines) - 2):
        if lines[i].startswith("--- ") and lines[i + 1].startswith("+++ ") and lines[i + 2].startswith("@@"):
            old, new = (line[4:].split("\t")[0].strip() for line in lines[i:i + 2])
            yield i, old.removeprefix("a/"), new.removeprefix("b/")


def diff_files(diff: str) -> tuple[set[str], set[str], set[str]]:
    """(고치는 기존 파일, 새로 만드는 파일, 지우는 파일).
    옛 이름과 새 이름이 다르면 둘 다 '고치는 파일'로 본다 (둘 다 묶음 안이어야 한다)."""
    changed, created, deleted = set(), set(), set()
    for _, old, new in _headers(diff.splitlines()):
        if new == "/dev/null":
            deleted.add(old)
        elif old == "/dev/null":
            created.add(new)
        else:
            changed |= {old, new}
    return changed, created, deleted


def with_git_headers(diff: str) -> str:
    """파일 머리줄을 diff_files()가 읽은 경로로 다시 쓴다 (삭제·확장 머리줄은 verify가 먼저 거절한다).
    - 'diff --git' 줄이 없으면 git apply --recount가 다음 파일의 '--- a/…'를 앞 hunk의 삭제 줄로 읽는다.
    - 접두어 없는 경로는 git이 첫 칸을 떼어 다른 파일에 적용한다 (검사한 파일 ≠ 바뀐 파일).
    - 모델이 쓴 'diff --git'·'index'·'new file mode' 줄은 버린다 (빠지거나 틀리면 적용이 실패한다)."""
    lines = diff.splitlines()
    heads = {i: (old, new) for i, old, new in _headers(lines)}
    out = []
    for i, line in enumerate(lines):
        if i in heads:
            old, new = heads[i]
            out += [f"diff --git a/{new} b/{new}", *(["new file mode 100644"] if old == "/dev/null" else []),
                    "--- " + ("/dev/null" if old == "/dev/null" else f"a/{new}"), f"+++ b/{new}"]
        elif i - 1 not in heads and not line.startswith(("diff --git ", "index ", "new file mode ")):
            out.append(line)        # i - 1이 머리줄이면 이 줄은 위에서 다시 쓴 '+++ '
    return "\n".join(out) + "\n"


def safe_path(path: str) -> bool:
    """diff가 사본 밖이나 .git을 건드리지 못하게."""
    parts = path.replace("\\", "/").split("/")
    return bool(path) and not path.startswith(("/", "\\")) and ":" not in parts[0] and ".." not in parts \
        and ".git" not in parts
