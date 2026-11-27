"""ChatGPT 클라이언트 인터페이스. 실제 구현은 llm/chatgpt.py(로그인은 llm/auth.py), 테스트는 tests/test_llm/fake_chatgpt.py."""
from typing import Protocol


class LLMError(RuntimeError):
    """kind: login(다시 로그인) / plan(구독 자격 없음, 403) / limit(사용량 한도, 429) / error(그 밖, 이 요청만 실패)."""

    def __init__(self, message: str, kind: str = "error"):
        super().__init__(message)
        self.kind = kind


class Client(Protocol):
    model: str

    def ask(self, instructions: str, payload: dict, effort: str) -> dict:
        """payload(JSON)를 보내고 JSON 객체 하나를 받는다. effort: 추론 강도 (low·medium·high). 실패하면 LLMError."""


def connected() -> Client | None:
    """로그인한 ChatGPT 클라이언트, 로그인 전이면 None (AI 단계를 건너뛴다). 네트워크는 쓰지 않는다 (첫 요청 때 쓴다)."""
    from wescope.llm import auth, chatgpt      # auth·chatgpt가 이 모듈의 LLMError를 쓰므로 여기서 불러온다
    return chatgpt.ChatGPT() if auth.status()["state"] == "ready" else None
