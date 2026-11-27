"""실제 ChatGPT 클라이언트 (v0.2 inference.py 이식): 내 구독으로 Responses API를 스트리밍 호출, 대화는 저장하지 않는다(store: false)."""
import functools
import http.client
import json
import time
from contextlib import contextmanager

from wescope.llm import auth
from wescope.llm.client import LLMError

MAX_TEXT = 200_000        # 응답 글자 수 상한 (수정안 diff 상한 MAX_DIFF의 두 배)
DEADLINE = 180            # 응답 하나를 다 받을 때까지 기다리는 초
_KINDS = {401: "login", 403: "plan", 429: "limit"}
_MESSAGES = {401: "ChatGPT 연결이 만료됐어요. 다시 연결하세요",
             403: "ChatGPT 구독 사용 자격이 없어요. Plus 이상 구독이 필요해요",
             429: "ChatGPT 사용량 한도에 도달했어요"}


@contextmanager
def _guarded():
    """읽는 도중의 오류(시간 초과·끊긴 스트림·깨진 JSON·토큰 잠금 대기 초과)도 LLMError로.
    LLMError가 아니면 AI 단계만이 아니라 검사 전체가 실패한다. 메시지에는 오류 이름만 (내용에 주소·토큰이 있을 수 있다)."""
    try:
        yield
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise LLMError(f"ChatGPT 응답을 받지 못했어요 ({type(error).__name__})") from None


def _request(method: str, path: str, *, data: bytes | None = None, accept="application/json"):
    """401이면 저장된 만료 시각과 상관없이 토큰을 새로 받아 한 번 더. 그래도 401이면 저장된 로그인을 지운다
    (그래야 대시보드가 '연결됨' 대신 [ChatGPT 연결] 버튼을 보인다)."""
    for retry in (True, False):
        headers = {"Authorization": "Bearer " + auth.access_token(), "Accept": accept}
        if data is not None:
            headers["Content-Type"] = "application/json"
        response = auth.http(method, auth.RESOURCE + path, data=data, headers=headers, timeout=60)
        if response.status == 200:
            return response
        status = response.status
        response.close()
        if status != 401:
            break
        if retry:
            auth.expire()
        else:
            auth.logout()
    raise LLMError(_MESSAGES.get(status, f"ChatGPT 요청이 실패했어요 (HTTP {status})"), _KINDS.get(status, "error"))


def collect(lines) -> str:
    """SSE 줄들 → 모델이 낸 글 전체. 완료 이벤트가 오기 전에 끊기거나 너무 길면 LLMError."""
    chunks, size, deadline = [], 0, time.monotonic() + DEADLINE
    for line in lines:
        if time.monotonic() > deadline:
            break
        line = line.strip()
        if not line.startswith(b"data:"):
            continue
        raw = line[5:].strip()
        if raw == b"[DONE]":
            break
        event = json.loads(raw)
        kind = event.get("type")
        if kind == "response.output_text.delta" and isinstance(event.get("delta"), str):
            size += len(event["delta"])
            if size > MAX_TEXT:
                break
            chunks.append(event["delta"])
        elif kind == "response.completed":
            return "".join(chunks)
        elif kind in ("error", "response.failed", "response.incomplete"):
            break
    raise LLMError("ChatGPT 응답을 끝까지 받지 못했어요")


def parse(text: str) -> dict:
    """모델 글 → JSON 객체. 코드 블록(```json … ```)으로 감싸 오면 벗긴다."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    try:
        answer = json.loads(text)
    except ValueError:
        raise LLMError("ChatGPT 응답이 JSON이 아니에요") from None
    if not isinstance(answer, dict):
        raise LLMError("ChatGPT 응답이 JSON 객체가 아니에요")
    return answer


class ChatGPT:
    @functools.cached_property
    def model(self) -> str:
        """구독에서 쓸 수 있는 모델 중 첫 번째. shortcut: 모델 고르기 설정 없음, 필요해지면 설정 창(F4)에 둔다."""
        with _guarded(), _request("GET", "/models") as response:
            for model in json.load(response).get("models", []):
                if model.get("visibility") == "list" and model.get("slug"):
                    return model["slug"]
        raise LLMError("이 계정에서 쓸 수 있는 모델이 없어요", "plan")

    def ask(self, instructions: str, payload: dict) -> dict:
        body = json.dumps({"model": self.model, "store": False, "stream": True, "instructions": instructions,
                           "input": [{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]},
                          ensure_ascii=False).encode()
        with _guarded(), _request("POST", "/responses", data=body, accept="text/event-stream") as response:
            return parse(collect(response))
