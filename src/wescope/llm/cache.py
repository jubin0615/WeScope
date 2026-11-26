"""~/.wescope/ai-cache — ChatGPT 응답 캐시 (AI.md §7).

키 = 모델·프롬프트 버전·지시·보낸 내용(자리표시 처리된 코드·맥락) 전체의 해시. 코드가 같으면 다시 요청하지 않아
같은 결과가 나온다. 보낸 내용에 비밀값 원문이 없으므로 응답에도 없다.
"""
import hashlib
import json
import os

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
