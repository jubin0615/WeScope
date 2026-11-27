"""WS-01 비밀값 노출. 가장 먼저 실행되어 ctx.secrets를 채운다 (이후 모든 출력의 마스킹 기준)."""
import re
from fnmatch import fnmatch
from pathlib import PurePosixPath

import pathspec

from wescope.analyzers.base import Analyzer, AnalyzerResult
from wescope.analyzers.secrets import patterns as P
from wescope.models.finding import RawHit, lower_severity

_FILE_RULES = {"env": "secret-env-file", "credential": "secret-credential-file", "data": "secret-data-file"}
_BASE_SEVERITY = {"env": "CRITICAL", "credential": "CRITICAL", "data": "MEDIUM"}
_GITIGNORE_SAMPLES = {".env*": ".env", "*.pem": "server.pem", "*.key": "server.key",
                      "serviceAccountKey*.json": "serviceAccountKey.json", "*.tfstate": "terraform.tfstate"}


class SecretsAnalyzer(Analyzer):
    id = "secrets"
    categories = ("WS-01",)
    languages = frozenset({"*"})

    def run(self, ctx) -> AnalyzerResult:
        hits = self._sensitive_files(ctx) + self._git_hygiene(ctx)
        for path in ctx.text_files():
            if not P.is_test_file(path):
                hits += self._scan_text(ctx, path, ctx.text(path))
        return AnalyzerResult(hits)

    def _sensitive_files(self, ctx):
        """파일 존재형: 내용 대신 Git 상태로 판정 (RULES.md WS-01 '파일 존재형 규칙과 Git 상태')."""
        hits = []
        for item in ctx.sensitive_files:
            state, base = item["git"], _BASE_SEVERITY[item["kind"]]
            if state == "ignored":
                continue
            if state is None:
                severity, confidence, why = "MEDIUM", "Potential", "공유·배포할 때 포함되지 않게 확인하세요"
            elif state == "untracked":
                severity, confidence, why = lower_severity(base), None, "아직 커밋되지 않았지만 .gitignore에 없어 다음 커밋에 들어갈 수 있어요"
            else:
                severity, confidence, why = base, None, "저장소에 커밋되어 있어요"
            hits.append(RawHit(_FILE_RULES[item["kind"]], item["path"], 0, evidence=f"{item['path']} — {why}",
                               severity=severity, confidence=confidence, extra={"kind": state or "no-git"}))
        return hits

    def _git_hygiene(self, ctx):
        if not ctx.source.get("git"):
            return []
        if ctx.git_ignores:   # 저장소의 하위 폴더를 연결: 루트 쪽 .gitignore까지 Git이 판정한다
            covered = ctx.git_ignores(list(_GITIGNORE_SAMPLES.values()))
            missing = [pattern for pattern, sample in _GITIGNORE_SAMPLES.items() if sample not in covered]
        else:
            text = ctx.text(".gitignore") if ".gitignore" in ctx.files else None
            if text is None:
                return [RawHit("git-hygiene", ".gitignore", 0, evidence=".gitignore 파일이 없어요", extra={"kind": "missing"})]
            spec = pathspec.PathSpec.from_lines("gitwildmatch", text.splitlines())
            missing = [pattern for pattern, sample in _GITIGNORE_SAMPLES.items() if not spec.match_file(sample)]
        if not missing:
            return []
        return [RawHit("git-hygiene", ".gitignore", 0, evidence="등록되지 않은 패턴: " + ", ".join(missing),
                       severity="HIGH" if ".env*" in missing else "MEDIUM", extra={"kind": "incomplete"})]

    def _scan_text(self, ctx, path, text):
        rule = _rule_for(path)
        client = P.is_client_file(path, text)
        bare = rule in ("secret-infra-config", "secret-dev-tool") or path.endswith(P.CONFIG_SUFFIXES)
        hits, seen_env = [], set()
        in_key = False
        for number, line in enumerate(text.splitlines(), 1):
            in_key = _register_key_body(ctx, line, in_key)
            found = list(_provider_values(line))
            if rule != "secret-doc":
                known = [v for _, v, _ in found if v]
                found += [n for n in _named_values(line, bare, rule == "secret-dev-tool", path.endswith(".py"))
                          if not any(k in n[1] for k in known)]   # 공급자 형식으로 이미 잡은 값은 한 번만
            for kind, value, critical in found:
                if value:
                    ctx.secrets.register(value)
                line_rule = "secret-client-bundle" if client and kind in P.HIGH_PRIVILEGE else rule
                hits.append(RawHit(line_rule, path, number, evidence=line.strip(),
                                   severity="CRITICAL" if critical and line_rule != "secret-doc" else None,
                                   extra={"kind": kind}))
            for match in P.FRONTEND_ENV.finditer(line):
                name = match["name"]
                if (P.FRONTEND_SECRET_WORD.search(name) and not P.FRONTEND_PUBLIC_WORD.search(name)
                        and name not in seen_env):
                    seen_env.add(name)
                    hits.append(RawHit("secret-frontend-env", path, number, evidence=line.strip(), extra={"kind": name}))
        return hits


def _register_key_body(ctx, line, in_key) -> bool:
    """PEM 개인키 본문을 가릴 값으로 등록한다. 돌려주는 값: 다음 줄도 본문인가.
    한 줄 문자열('-----BEGIN ...-----\\nMIIC...\\n-----END ...')과 여러 줄 PEM(머리줄 다음 줄부터 END까지)을 모두 다룬다."""
    header = P.PRIVATE_KEY.search(line)
    if not header and not in_key:
        return False
    body, end, _ = line[header.end() if header else 0:].partition("-----END")
    # 문자열 안의 \n·\r 이스케이프와 따옴표를 걷어 내고 base64 조각만 남긴다 (+는 base64 글자라 나누지 않는다)
    chunks = [t for t in re.split(r"\\[rnt]|[\s\"'`,;]", body) if P.PEM_CHUNK.fullmatch(t)]
    for chunk in chunks:
        ctx.secrets.register(chunk)
    return not end and bool(header or chunks)


def _rule_for(path: str) -> str:
    name = PurePosixPath(path).name
    if path.endswith(P.DOC_SUFFIXES):
        return "secret-doc"
    if any(fnmatch(name, p) for p in P.INFRA_FILES) or (path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))):
        return "secret-infra-config"
    if any(path == p or path.endswith("/" + p) for p in P.DEV_TOOL_FILES):
        return "secret-dev-tool"
    return "secret-hardcoded"


def _provider_values(line):
    """(종류, 등록할 값, CRITICAL 여부). 형식 자체가 증거라 환경변수 참조가 같은 줄에 있어도 잡는다."""
    for kind, pattern, critical in P.PROVIDERS:
        for match in pattern.finditer(line):
            value = match.group(0)
            if P.is_placeholder(value):
                continue
            if kind == "jwt":
                role = P.jwt_role(value)
                if role == "anon":
                    continue          # Supabase anon 키는 공개용
                if role == "service_role":
                    kind, critical = "jwt-service-role", True
            yield kind, value, critical
    if P.PRIVATE_KEY.search(line):
        yield "private-key", None, True   # 본문은 _register_key_body가 등록한다
    for match in P.CONNECTION.finditer(line):
        if not P.is_placeholder(match["value"]) and match["value"].lower() not in ("password", "pass"):
            yield "connection-string", match["value"], False


def _named_values(line, bare, dev_tool, python):
    """인증정보 이름 변수에 들어간 리터럴 값."""
    if P.ENV_REFERENCE.search(line):
        return
    matches = list(P.ASSIGN_QUOTED.finditer(line))
    if bare:
        matches += list(P.ASSIGN_BARE.finditer(line)) + list(P.DOCKER_ENV.finditer(line))
    if dev_tool:
        matches += [m for m in P.NETRC.finditer(line)]
    seen = set()
    for match in matches:
        value = match["value"]
        name = match.groupdict().get("name") or "password"
        normalized = P.credential_name(name)
        if not normalized or value in seen or P.is_placeholder(value) or P.entropy(value) < 2.5:
            continue
        if python and normalized in P.SIGNING_KEY_NAMES and (len(value) < 32 or value.lower() in P.WEAK_SIGNING_VALUES):
            continue          # Python의 약한 서명 키는 config-weak-secret이 맡는다
        seen.add(value)
        yield "named:" + normalized, value, False
