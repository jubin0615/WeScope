"""ChatGPT 클라이언트 인터페이스. 실제 구현(Sign in with ChatGPT)은 B8-2, 테스트는 tests/test_llm/fake_chatgpt.py."""
from typing import Protocol


class LLMError(RuntimeError):
    """kind: login(다시 로그인) / plan(구독 자격 없음, 403) / limit(사용량 한도, 429) / error(그 밖, 이 요청만 실패)."""

    def __init__(self, message: str, kind: str = "error"):
        super().__init__(message)
        self.kind = kind


class Client(Protocol):
    model: str

    def ask(self, instructions: str, payload: dict) -> dict:
        """payload(JSON)를 보내고 JSON 객체 하나를 받는다. 실패하면 LLMError."""


def connected() -> Client | None:
    """로그인한 ChatGPT 클라이언트. 로그인 전·B8-2 전에는 None (AI 단계를 건너뛴다)."""
    return None
