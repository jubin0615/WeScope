"""~/.wescope/config.toml — 전역 설정 (대시보드 설정 창에서 편집, ARCHITECTURE §6)."""
import json
import os
import tomllib

from wescope.paths import home

CHOICES = {"theme": ("system", "light", "dark")}   # 키 → 허용 값 (첫 값이 기본값)


def _path():
    return home() / "config.toml"


def load() -> dict:
    """손으로 고친 파일이 깨졌거나 값이 틀려도 기본값으로 동작한다."""
    try:
        saved = tomllib.loads(_path().read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        saved = {}
    return {key: saved[key] if saved.get(key) in allowed else allowed[0] for key, allowed in CHOICES.items()}


def save(changes: dict) -> dict:
    current = {**load(), **changes}
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    # shortcut: 문자열 값만 쓴다 (JSON 문자열 표기는 TOML 기본 문자열로도 유효). 표·배열이 필요해지면 TOML 작성기를 쓴다
    temp.write_text("".join(f"{key} = {json.dumps(value, ensure_ascii=False)}\n" for key, value in current.items()),
                    encoding="utf-8")
    os.replace(temp, path)
    return current
