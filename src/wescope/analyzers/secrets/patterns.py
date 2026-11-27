"""WS-01 패턴과 오탐 필터 (RULES.md §2 WS-01, 오탐 필터 표)."""
import base64
import json
import math
import re
from collections import Counter
from pathlib import PurePosixPath

# (종류, 정규식, CRITICAL 여부). anthropic이 openai보다 먼저 와야 sk-ant-가 openai로 잡히지 않는다.
PROVIDERS = [
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), False),
    ("openai", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}"), False),
    ("stripe", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}"), False),
    ("aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), False),
    ("gitlab", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), False),
    ("slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), False),
    ("webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"
                           r"|https://(?:discord|discordapp)\.com/api/webhooks/\d+/[\w-]{20,}"), False),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), False),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
PEM_CHUNK = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")   # 개인키 본문 한 조각 (base64)
CONNECTION = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)"
                        r"://[^\s:@/'\"]*:(?P<value>[^\s@/'\"]+)@")
HIGH_PRIVILEGE = {"anthropic", "openai", "stripe", "aws", "jwt-service-role", "private-key"}

# 인증정보 이름: 소문자·구분자 제거 후 이 단어로 끝나야 한다 (tokenizer·token_type 같은 이름 제외)
CREDENTIAL_NAME = re.compile(r"(password|passwd|pwd|secret|token|apikey|accesskey|privatekey|clientsecret"
                             r"|secretkey|authkey)$|^auth$")
ASSIGN_QUOTED = re.compile(r"""(?P<name>[A-Za-z_][\w.-]*)["']?\s*(?:=|:|=>)\s*["'](?P<value>[^"'\n]{8,})["']""")
ASSIGN_BARE = re.compile(r"""(?:^|[\s\-:/])(?P<name>[A-Za-z_][\w.-]*)["']?\s*[:=]\s*(?P<value>[^\s"'#,]{8,})""")
DOCKER_ENV = re.compile(r"^\s*(?:ENV|ARG)\s+(?P<name>\w+)\s+(?P<value>[^\s=]{8,})\s*$")
NETRC = re.compile(r"\bpassword\s+(?P<value>\S{4,})")
# 서명 키 이름 — Python에서 약한 값이면 config-weak-secret이 맡는다
SIGNING_KEY_NAMES = {"secretkey", "jwtsecret", "jwtsecretkey", "sessionsecret", "appsecretkey", "flasksecretkey"}
WEAK_SIGNING_VALUES = {"secret", "changeme", "dev", "development", "secret-key", "secretkey", "mysecret",
                       "supersecret", "keyboard cat", "your-secret-key", "default", "password", "test"}

FRONTEND_ENV = re.compile(r"\b(?P<name>(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_)[A-Z0-9_]+)")
FRONTEND_SECRET_WORD = re.compile(r"SECRET|PASSWORD|PRIVATE|SERVICE_ROLE|TOKEN")
FRONTEND_PUBLIC_WORD = re.compile(r"ANON_KEY|PUBLISHABLE_KEY|PUBLIC_KEY")

ENV_REFERENCE = re.compile(r"process\.env|os\.environ|os\.getenv|getenv\(|import\.meta\.env|System\.getenv")
_PLACEHOLDER_WORDS = ("your", "example", "changeme", "change_me", "change-me", "xxx", "dummy", "placeholder",
                      "sample", "fake", "replace", "...", "here", "redacted", "todo", "test", "<", ">", "***")
_HANGUL = re.compile(r"[가-힣]")

INFRA_FILES = ("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml", "Dockerfile*",
               ".gitlab-ci.yml", "vercel.json", "netlify.toml", "fly.toml", "wrangler.toml")
DEV_TOOL_FILES = (".npmrc", ".pypirc", ".netrc", ".docker/config.json", ".vscode/launch.json", ".vscode/settings.json")
CONFIG_SUFFIXES = (".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties")
CLIENT_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".svelte", ".html")
DOC_SUFFIXES = (".md", ".mdx", ".rst")


def is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    return (v.startswith(("$", "{{", "%(", "{")) or any(w in v for w in _PLACEHOLDER_WORDS)
            or len(set(v)) <= 3 or " " in v or bool(_HANGUL.search(v)))


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def credential_name(name: str) -> str | None:
    """인증정보 이름이면 정규화한 이름, 아니면 None."""
    normalized = re.sub(r"[_\-]", "", name.split(".")[-1].lower())
    return normalized if CREDENTIAL_NAME.search(normalized) else None


def jwt_role(token: str) -> str | None:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("role")
    except (ValueError, IndexError, AttributeError):
        return None


def is_test_file(path: str) -> bool:
    p = PurePosixPath(path)
    parts = {part.lower() for part in p.parts[:-1]}
    name = p.name.lower()
    return bool(parts & {"tests", "test", "__tests__", "fixtures", "spec", "__mocks__"}) or ".test." in name \
        or ".spec." in name or name.startswith("test_") or name.endswith("_test.py")


def is_client_file(path: str, text: str) -> bool:
    if not path.endswith(CLIENT_SUFFIXES):
        return False
    if text.lstrip().startswith(("'use client'", '"use client"')):
        return True
    parts = PurePosixPath(path).parts
    under_app = parts[0] == "app" or parts[:2] == ("src", "app")
    return "components" in parts or parts[0] == "public" or (
        (under_app or "pages" in parts) and "api" not in parts and not PurePosixPath(path).stem == "route")
