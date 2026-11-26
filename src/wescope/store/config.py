"""~/.wescope/config.toml — 전역 설정 (대시보드 설정 창에서 편집, ARCHITECTURE §6)."""
import json
import os
import tomllib

from wescope.paths import home

# 키 → 허용 값 (첫 값이 기본값)
CHOICES = {
    "theme": ("system", "light", "dark"),
    "ai_level": ("deep", "basic", "off"),   # ChatGPT 분석 수준 (AI.md §2). 연결했을 때 기본은 심층
    "ai_on_hook": (False, True),            # 커밋 자동 검사에서도 ChatGPT 사용 (사용자가 없는 동안 구독을 쓰므로 기본 끔)
}


def _path():
    return home() / "config.toml"


def load() -> dict:
    """손으로 고친 파일이 깨졌거나 값이 틀려도 기본값으로 동작한다."""
    try:
        saved = tomllib.loads(_path().read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        saved = {}
    return {key: saved[key] if is_allowed(saved.get(key), choices) else choices[0] for key, choices in CHOICES.items()}


def is_allowed(value, choices) -> bool:
    """True == 1 이라 in만 쓰면 숫자 1이 불 값으로 통과한다. 형까지 같아야 한다."""
    return any(type(value) is type(c) and value == c for c in choices)


def save(changes: dict) -> dict:
    current = {**load(), **changes}
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    # shortcut: 문자열·불 값만 쓴다 (JSON 표기 그대로 TOML에서도 유효). 표·배열이 필요해지면 TOML 작성기를 쓴다
    temp.write_text("".join(f"{key} = {json.dumps(value, ensure_ascii=False)}\n" for key, value in current.items()),
                    encoding="utf-8")
    os.replace(temp, path)
    return current
