"""~/.wescope/ai-cache — ChatGPT 응답 캐시 (AI.md §7).

키 = 모델·프롬프트 버전·지시·보낸 내용(자리표시 처리된 코드·맥락) 전체의 해시. 코드가 같으면 다시 요청하지 않아
같은 결과가 나온다. 보낸 내용에 비밀값 원문이 없으므로 응답에도 없다.
"""
import hashlib
import json
import os

from wescope.llm.client import LLMError
from wescope.paths import home


def key(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def get(cache_key: str) -> dict | None:
    try:
        return json.loads((home() / "ai-cache" / f"{cache_key}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def put(cache_key: str, answer: dict):
    folder = home() / "ai-cache"
    folder.mkdir(parents=True, exist_ok=True)
    temp = folder / f"{cache_key}.tmp"
    temp.write_text(json.dumps(answer, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, folder / f"{cache_key}.json")
    # shortcut: 지우지 않고 쌓인다 (응답 하나 수 KB). 커지면 오래된 것부터 정리


class Session:
    """한 검사(또는 요청 시 생성 한 번)의 ChatGPT 요청. 캐시를 먼저 보고, 요청 수·캐시 적중 수를 센다.
    작업(수정안·의심 확인·보완 탐지)마다 자기 지시문과 프롬프트 버전을 넘긴다: 둘 다 캐시 키에 들어간다."""

    def __init__(self, client):
        self.client = client
        self.model = None
        self.stats = {"requests": 0, "cache_hits": 0}

    def ask(self, instructions: str, version: str, payload: dict) -> tuple[dict, str]:
        self.model = self.client.model      # 실제 클라이언트는 첫 요청 때 모델 목록을 받는다 (실패하면 LLMError)
        cache_key = key(self.model, version, instructions, payload)
        answer = get(cache_key)
        if answer is not None:
            self.stats["cache_hits"] += 1
            return answer, cache_key
        self.stats["requests"] += 1
        answer = self.client.ask(instructions, payload)
        if not isinstance(answer, dict):
            raise LLMError("ChatGPT 응답이 JSON 객체가 아니에요")
        put(cache_key, answer)
        return answer, cache_key
