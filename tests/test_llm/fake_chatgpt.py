"""가짜 ChatGPT: 정해 둔 응답을 돌려주고 받은 요청을 모두 기록한다. 실제 로그인 없이 B8 기능을 끝까지 시험한다."""


class FakeChatGPT:
    model = "fake-gpt"

    def __init__(self, respond):
        """respond(payload) → 응답 dict, 또는 던질 예외. 같은 묶음의 두 번째 요청이면 payload에 previous_attempt가 있다."""
        self.respond = respond
        self.requests: list[dict] = []

    def ask(self, instructions: str, payload: dict) -> dict:
        self.requests.append(payload)
        answer = self.respond(payload)
        if isinstance(answer, Exception):
            raise answer
        return answer


def answer(diff: str, **fields) -> dict:
    return {"summary_ko": "고쳤어요", "diff": diff, "files": [], "behavior_change_ko": "없음", "follow_ups": [],
            "new_dependencies": [], "test_hint_ko": "다시 스캔하세요", "confidence": "high", **fields}


def sent_lines(payload: dict, path: str) -> dict[int, str]:
    """보낸 파일 내용('  18| 코드') → {줄 번호: 코드}."""
    content = next(f["content"] for f in payload["files"] if f["path"] == path)
    rows = (row.partition("| ") for row in content.splitlines() if "| " in row)
    return {int(number): code for number, _, code in rows}


def replace_lines(payload: dict, path: str, changes: dict[str, str]) -> str:
    """needle이 든 줄 → 새 줄. 보낸 코드를 보고 앞뒤 한 줄 문맥이 있는 diff를 만든다 (모델이 하는 일)."""
    lines = sent_lines(payload, path)
    new_at = {next(n for n, code in lines.items() if needle in code): new for needle, new in changes.items()}
    start, end = min(new_at) - 1, max(new_at) + 1          # 바꾸는 줄 전체를 한 hunk로 (hunk끼리 겹치지 않게)
    body = "".join(f"-{lines[n]}\n+{new_at[n]}\n" if n in new_at else f" {lines[n]}\n" for n in range(start, end + 1))
    count = end - start + 1
    return f"--- a/{path}\n+++ b/{path}\n@@ -{start},{count} +{start},{count} @@\n{body}"
