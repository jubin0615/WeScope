"""Track D: 민감 파일 판별. 이 파일들은 내용을 읽지도, 임시 폴더로 복사하지도 않는다."""
import re
from fnmatch import fnmatch
from pathlib import PurePosixPath

_ENV = re.compile(r"^\.env(\.[\w.-]+)?$")
_ENV_SAFE = (".example", ".sample", ".template", ".dist", ".defaults")
_CREDENTIAL = (
    "serviceaccountkey*.json", "*-service-account.json", "credentials.json", "client_secret*.json",
    "application_default_credentials.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "terraform.tfstate", "terraform.tfstate.backup", "*.tfvars", ".pgpass",
)
# shortcut: *.sql은 이름에 dump·backup이 있을 때만 덤프로 본다 (마이그레이션 SQL을 읽어야 하므로). 오탐·미탐이 보이면 크기·INSERT 비율로 판별.
_DATA = ("*.sqlite", "*.sqlite3", "*.db", "*.dump", "*.bak", "*.log", "*dump*.sql", "*backup*.sql")


def kind(rel_path: str) -> str | None:
    """'env' / 'credential' / 'data' / None"""
    path = PurePosixPath(rel_path)
    name = path.name.lower()
    if _ENV.match(name) and not name.endswith(_ENV_SAFE):
        return "env"
    if any(fnmatch(name, p) for p in _CREDENTIAL) or rel_path.endswith(".kube/config"):
        return "credential"
    if any(fnmatch(name, p) for p in _DATA):
        return "data"
    return None
