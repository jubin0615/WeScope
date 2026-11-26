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


def diff_files(diff: str) -> tuple[set[str], set[str]]:
    """(고치는 기존 파일, 새로 만드는 파일). 경로는 a/·b/ 접두어를 뗀 상대 경로."""
    changed, created = set(), set()
    old = None
    for line in diff.splitlines():
        if line.startswith("--- "):
            old = line[4:].split("\t")[0].strip()
        elif line.startswith("+++ ") and old is not None:
            new = line[4:].split("\t")[0].strip()
            if new != "/dev/null":
                (created if old == "/dev/null" else changed).add(new.removeprefix("b/"))
            old = None
    return changed, created


def safe_path(path: str) -> bool:
    """diff가 사본 밖이나 .git을 건드리지 못하게."""
    parts = path.replace("\\", "/").split("/")
    return bool(path) and not path.startswith(("/", "\\")) and ":" not in parts[0] and ".." not in parts \
        and ".git" not in parts
