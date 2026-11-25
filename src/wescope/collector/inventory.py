"""AppProfile: 언어·프레임워크·매니페스트 (AI 없이 결정론적으로)."""
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath


@dataclass
class AppProfile:
    languages: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)


LANGUAGES = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".kt": "kotlin", ".php": "php",
    ".rb": "ruby", ".go": "go", ".cs": "csharp",
}
MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "package-lock.json",
             "pnpm-lock.yaml", "yarn.lock", "uv.lock", "Dockerfile", "pom.xml", "build.gradle"}
_FRAMEWORKS = {
    "flask": re.compile(r"^\s*(from\s+flask\b|import\s+flask\b)", re.M),
    "fastapi": re.compile(r"^\s*(from\s+fastapi\b|import\s+fastapi\b)", re.M),
    "django": re.compile(r"^\s*(from\s+django\b|import\s+django\b)", re.M),
    "express": re.compile(r"""require\(\s*['"]express['"]\s*\)|from\s+['"]express['"]"""),
    "nextjs": re.compile(r"""from\s+['"]next(/[\w/-]+)?['"]"""),
}


def language(path: str) -> str | None:
    return LANGUAGES.get(PurePosixPath(path).suffix.lower())


def build(ctx) -> AppProfile:
    languages = Counter(lang for p in ctx.all_files if (lang := language(p)))
    frameworks = set()
    for path in ctx.files:
        if language(path) and (text := ctx.text(path)):
            frameworks.update(name for name, pattern in _FRAMEWORKS.items() if pattern.search(text))
    manifests = [p for p in ctx.all_files if PurePosixPath(p).name in MANIFESTS]
    return AppProfile(dict(sorted(languages.items())), sorted(frameworks), manifests)
