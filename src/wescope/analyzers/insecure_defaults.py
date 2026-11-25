"""WS-06 줄 패턴 (Python·JS/TS 공통): TLS 검증 해제·약한 해시·기본 계정·오류 노출·JS fail-open·보안 TODO."""
import re

from wescope.analyzers.base import Analyzer, AnalyzerResult
from wescope.collector.inventory import language
from wescope.models.finding import RawHit

_RULES = [
    ("config-tls-verify-off", re.compile(
        r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"
        r"|ssl\._create_unverified_context|\bCERT_NONE\b")),
    ("config-default-credential", re.compile(
        r"""['"](?:admin|root)['"][^'"\n]{1,40}?['"](?:admin|password|root|1234|12345678|admin123|toor)['"]""",
        re.I)),
    ("config-error-exposure", re.compile(
        r"\b(?:return|jsonify|send|json|render|write)\b.*(?:traceback\.format_exc\(\)|\bstr\((?:e|err|exc|ex|error)\)"
        r"|\b(?:err|error|e|ex)\.(?:stack|message)\b)")),
    ("config-fail-open", re.compile(r"catch\s*(?:\(\s*\w*\s*\))?\s*\{\s*(?:return\s+)?next\(\s*\)")),
]
_WEAK_HASH = re.compile(r"hashlib\.(?:md5|sha1)\(|createHash\(\s*['\"](?:md5|sha1)['\"]", re.I)
_PASSWORD_WORD = re.compile(r"passw|pwd", re.I)
_TODO = re.compile(r"(?:#|//|/\*|\*)\s*.*\b(?:TODO|FIXME|HACK)\b.*(?:auth|login|permission|csrf|saniti|verify|password"
                   r"|secret|token|security|권한|인증|검증|보안)", re.I)


class InsecureDefaultsAnalyzer(Analyzer):
    id = "insecure_defaults"
    categories = ("WS-06",)
    languages = frozenset({"python", "javascript", "typescript"})

    def applies(self, ctx):
        return any(lang in ctx.profile.languages for lang in self.languages)

    def run(self, ctx) -> AnalyzerResult:
        hits = []
        for path in ctx.text_files():
            if language(path) not in self.languages:
                continue
            lines = ctx.text(path).splitlines()
            for number, line in enumerate(lines, 1):
                stripped = line.strip()
                for rule, pattern in _RULES:
                    if pattern.search(line):
                        hits.append(RawHit(rule, path, number, evidence=stripped))
                # 약한 해시는 앞뒤 3줄 안에 비밀번호 문맥이 있을 때만
                if _WEAK_HASH.search(line) and _PASSWORD_WORD.search("\n".join(lines[max(0, number - 4):number + 3])):
                    hits.append(RawHit("config-weak-hash", path, number, evidence=stripped))
                if _TODO.search(line):
                    hits.append(RawHit("config-security-todo", path, number, evidence=stripped))
        return AnalyzerResult(hits)
