<p align="center">
  <img src="docs/assets/wescope-banner.svg" alt="WeScope — 바이브코딩으로 만든 웹앱을 위한 로컬 보안 진단 도구" width="100%">
</p>

# We-Scope

**바이브코딩으로 만든 웹앱의 보안 실수를 내 PC에서 찾고, 왜 위험한지와 어떻게 고치는지를 한국어로 알려 줍니다.**

We-Scope는 AI 코딩 도구로 만든 웹 애플리케이션 저장소를 사용자 PC에서 분석하는 로컬 대시보드형 보안 진단 도구입니다. 보안 취약점 후보를 **We-Scope Top 10**과 **OWASP Top 10:2025** 기준으로 분류하고, 사용자 본인의 ChatGPT 구독을 연결하면 **로컬에서 적용·문법·재검사까지 확인한 수정안(diff)** 을 함께 만들어 줍니다.

```bash
git clone https://github.com/jubin0615/WeScope.git
cd WeScope
pip install -e .
wescope
```

> **정적 검사는 내 PC에서만 실행됩니다.** ChatGPT를 연결하면 위험이 있는 코드와 관련 파일(비밀값은 가림)이 내 ChatGPT 계정으로 전송됩니다. 저장소 전체와 `.env`는 보내지 않습니다.

---

## 목차

- [왜 We-Scope인가](#왜-we-scope인가)
- [주요 기능](#주요-기능)
- [보안 표준 매핑 / 탐지 패턴](#보안-표준-매핑--탐지-패턴)
- [기존 도구와의 차이점](#기존-도구와의-차이점)
- [사용법](#사용법)
- [동작 원리](#동작-원리)
- [보안·개인정보 원칙](#보안개인정보-원칙)
- [지원 범위와 한계](#지원-범위와-한계)
- [기술 스택](#기술-스택)
- [개발·테스트](#개발테스트)
- [로드맵](#로드맵)
- [문서](#문서)

---

## 왜 We-Scope인가

ChatGPT·Claude·Cursor 같은 도구 덕분에 누구나 며칠 만에 웹서비스를 만들 수 있게 되었습니다. 그런데 AI가 만든 코드에는 다음과 같은 실수가 자주 섞입니다.

- 소스에 그대로 박힌 API 키, 커밋된 `.env`, `NEXT_PUBLIC_`으로 브라우저에 노출된 서버 키
- f-string으로 만든 SQL, `innerHTML`, `eval(req.body…)`
- 프론트에서만 숨기고 API는 열어 둔 관리자 기능, 남의 `id`로도 조회되는 API
- `debug=True`, CORS `*`, `verify=False`, 쿠키 보안 속성 누락
- 서명을 검증하지 않는 JWT, 기본 계정·약한 서명 키

기존 방법은 각각 빈틈이 있습니다.

| 기존 방법 | 빈틈 |
|---|---|
| Semgrep·Bandit·ESLint 같은 정적 분석기 | 경고가 영어 위주이고 난해해서, 초보자는 무엇을 고쳐야 하는지 알기 어렵습니다 |
| gitleaks 같은 시크릿 스캐너 | 시크릿만 봅니다. 인가 누락·주입·설정 실수는 범위 밖입니다 |
| AI에게 "내 코드 보안 점검해 줘" | 매번 결과가 다르고 무엇을 검사했는지 알 수 없습니다. 코드를 짠 AI가 자기 맹점을 그대로 공유합니다 |
| 자율 침투 도구 | 공격 관점의 블랙박스 1회성 진단입니다. 소스를 보지 않고, 수정 방법이 산출물이 아닙니다 |

We-Scope는 **결정론적 정적 분석(항상 같은 기준) + OWASP 분류 + 한국어 설명 + 커밋 추적 + 선택적 ChatGPT 분석**으로 이 간극을 메웁니다.

- **명령어는 하나, 나머지는 대시보드에서** — 설치한 뒤에는 터미널에 `wescope` 한 단어만 입력합니다. 프로젝트 연결·검사·결과 확인·보고서·설정은 전부 브라우저 대시보드에서 합니다.
- **정적 분석이 기준선, ChatGPT가 그 위를 덮습니다** — 정적 분석은 누구에게나 같은 기준으로 기본 위험을 찾습니다. ChatGPT는 정적 분석이 놓치는 업무 로직·파일 간 흐름을 찾고, 의심 발견을 확인하고, 검증된 수정안을 만듭니다. ChatGPT는 정적 발견을 지우거나 분류를 바꿀 수 없습니다.
- **수정안이 핵심 산출물입니다** — 경고만 주지 않습니다. 모든 위험에 수정 방법을 주고, AI 코딩 도구에 그대로 붙여 넣을 수 있는 수정 요청 프롬프트를 만들어 줍니다.
- **결과는 "후보"입니다** — 정적 분석 결과로 안전을 보증하지 않습니다. 검사하지 못한 영역은 "발견 없음"과 구분해 "검사 안 함"으로 정직하게 표시합니다.

---

## 주요 기능

### 1. 실행부터 결과까지 대시보드 하나로

| 순간 | 동작 |
|---|---|
| `wescope` 입력 | `127.0.0.1`에 로컬 서버를 띄우고, 접속 티켓이 붙은 주소로 기본 브라우저를 엽니다 |
| 이미 실행 중일 때 다시 입력 | 새 서버를 띄우지 않고 열려 있는 대시보드를 다시 엽니다 |
| 시작 화면 | 프로젝트가 없으면 **프로젝트 폴더 경로** 또는 **GitHub 주소**를 입력하는 칸만 보입니다 |
| 검사 | 연결하면 바로 첫 검사를 하고, 이후에는 **[다시 스캔]** 또는 **커밋할 때마다 자동 검사**로 다시 봅니다 |

| 입력 | 검사 대상 |
|---|---|
| **프로젝트 폴더 경로** (Git 저장소여도, 아니어도 됨) | 폴더의 현재 파일을 임시 폴더로 복사해 검사합니다. 저장하지 않은 변경까지 반영되고, 원본 폴더는 건드리지 않습니다 |
| **GitHub 주소** | We-Scope 전용 폴더에 clone한 뒤 기본 브랜치(또는 지정한 브랜치)의 최신 커밋을 검사합니다. 비공개 저장소는 PC의 git 로그인 정보를 사용합니다 |

### 2. 비밀값 노출 탐지 (WS-01)

- **공급자 형식 키**: OpenAI·Anthropic·AWS·GitHub·GitLab·Stripe·Slack 키, Slack 웹훅, Supabase `service_role` JWT, 개인키 머리줄, DB 연결 문자열처럼 형식 자체가 증거인 값을 찾습니다. Supabase `anon` 키처럼 공개용인 키는 제외합니다.
- **인증정보 이름 변수**: `password`·`secret`·`token`·`api_key` 같은 이름의 변수에 들어간 리터럴을 찾습니다. 자리표시 값(`your-api-key`, `xxx`, `changeme` 등)과 환경변수 참조는 제외합니다.
- **파일 위치별 규칙**: 코드, 인프라·CI 설정(`docker-compose.yml`, GitHub Actions), 개발 도구 설정(`.npmrc`·`.netrc`), 문서(README의 curl 예시 등)를 나눠 판정합니다.
- **프론트엔드 노출**: `NEXT_PUBLIC_`·`VITE_` 등으로 브라우저에 실리는 비밀 이름 환경변수, 클라이언트 번들에 들어간 고권한 키를 따로 잡습니다.
- **민감 파일은 열지 않습니다**: `.env`, 서비스 계정 키, 개인키, `terraform.tfstate`, DB·로그 파일은 내용을 읽지 않고 경로와 종류만 기록합니다.
- **Git 상태로 판정합니다**: 같은 `.env`라도 커밋돼 있으면 CRITICAL, 아직 커밋 안 했지만 `.gitignore`에 없으면 한 단계 낮게, `.gitignore`로 제외돼 있으면 위험으로 보지 않습니다. Git이 아닌 폴더의 `.env`는 "공유·배포할 때 포함되지 않게 확인하세요"(Potential)로 알립니다.
- **Git 위생**: `.gitignore`가 없거나 `.env*`·`*.pem`·`*.key`·`serviceAccountKey*.json`·`*.tfstate`가 빠져 있으면 알려 줍니다.

### 3. 입력값 주입 탐지 (WS-05)

Semgrep taint 분석으로 **요청 입력값이 위험한 함수까지 흘러가는지** 확인합니다. SQL 인젝션, 명령어 인젝션, 코드 인젝션(`eval`), 경로 조작, SSRF, XSS, 오픈 리다이렉트, 위험한 파일 업로드, 안전하지 않은 역직렬화를 Python·JavaScript·TypeScript에서 찾습니다. 파라미터 바인딩·`shlex.quote`·`secure_filename`·허용 목록처럼 이미 막혀 있는 경로는 잡지 않습니다.

### 4. 인증·인가와 위험한 기본값 (WS-02, WS-06)

- **라우트 분석**: Flask·FastAPI·Express의 라우트를 추출해 인증 데코레이터·미들웨어·`Depends`·`before_request` 같은 가드를 찾습니다. 관리자 경로의 권한 확인 누락, 인증 없는 쓰기 API, 소유자 확인 없는 객체 조회(IDOR)를 찾습니다.
- **JWT**: 서명을 검증하지 않는 `jwt.decode`, `algorithms: ['none']`을 잡습니다.
- **설정**: `debug=True`, `ALLOWED_HOSTS = ['*']`, CORS 전체 허용(자격 증명 허용 포함), 쿠키 보안 속성 누락, 약한 서명 키, MD5·SHA-1 비밀번호 해시, TLS 검증 해제, 기본 계정, 오류·스택트레이스 노출, 실패 시 허용(fail-open), 예외 무시를 찾습니다.

### 5. 변화 추적과 커밋 자동 검사 (M2)

- **발견 지문**: `규칙 + 파일 + 정규화한 코드`로 지문을 만들어, 줄이 밀려도 같은 발견으로 봅니다. 비밀값은 가린 뒤에 지문을 만들어 원문 해시도 남기지 않습니다.
- **NEW / 그대로 / FIXED**: 직전 검사와 비교해 새로 생긴 위험과 해결된 위험을 보여 줍니다.
- **커밋할 때마다 자동 검사**: 로컬 Git 폴더에 post-commit hook을 설치합니다(기본 켬, 설정에서 끔). 커밋 직후 백그라운드에서 검사해 커밋을 느리게 하지 않습니다. 기존 hook은 그대로 두고 한 줄만 덧붙입니다.
- **알림 없음**: 자동 검사가 끝나도 토스트·배너를 띄우지 않습니다. 열려 있는 대시보드가 조용히 갱신되고, 닫혀 있으면 다음에 열 때 최신 결과가 보입니다.
- **오탐 표시**: [오탐이에요]로 표시한 발견은 다음 검사부터 점수·요약에서 빠집니다. 이유와 시각이 기록되고 언제든 해제할 수 있습니다.
- **이력·여러 프로젝트**: 검사별 위험 점수와 변화, 발견 이력을 로컬 SQLite에 남깁니다. 프로젝트 여러 개를 연결해 오갈 수 있습니다.

### 6. ChatGPT 분석 — 수정안 생성·검증, 의심 확인, 보완 탐지 (M3)

**Sign in with ChatGPT**로 사용자 본인의 구독을 씁니다. API 키도 서버 비용도 없습니다.

| 기능 | 내용 |
|---|---|
| **수정안 생성** | CRITICAL·HIGH 묶음마다 내 코드에 바로 적용할 수 있는 diff, 파일별 변경 설명, 동작 변화, 코드 밖에서 할 일(키 폐기·재발급 등), 확인 방법을 만듭니다. 프로젝트의 프레임워크·DB 라이브러리·관례를 맥락으로 함께 보냅니다 |
| **수정안 검증** | 받은 diff를 원본이 아닌 **임시 사본**에 `git apply`로 적용하고 → 문법 검사(Python `ast`, JS·TS tree-sitter) → 같은 탐지기로 재검사해 문제가 사라졌는지, 새 문제가 생기지 않았는지 확인합니다. 실패하면 이유를 붙여 한 번 더 고치게 합니다 |
| **검증 상태 표시** | **✓ 검증됨**(적용·문법·재검사 통과) / **◐ 문법 확인**(적용·문법은 통과, 재검사로는 판단 불가) / **○ 검증 안 됨**(참고용) |
| **의심 발견 확인** | "보호가 없어 보인다"(Potential)는 HIGH 이상 정적 발견을 미들웨어·호출 함수까지 읽고 확인합니다. 확인되면 `AI 확인`, 보호 코드를 찾으면 근거 줄을 실제 코드와 대조한 뒤 **오탐 제안**만 합니다. 오탐 처리는 항상 사용자가 합니다 |
| **보완 탐지** (심층) | 정적 분석이 원래 못 보는 곳 — 인가 로직, 결제·상태 전이, 대량 할당, 파일 간 흐름, 정적 규칙이 없는 언어 — 을 골라 검토합니다. 응답이 인용한 코드가 실제 코드와 다르면 버리고(환각 방지), 정해진 18개 유형에서만 골라 CWE·OWASP가 자동으로 붙습니다. AI 발견은 `AI` 태그와 Potential 신뢰도로 표시합니다 |
| **분석 수준** | 끔 / 기본(의심 확인 + 수정안) / **심층**(기본 + 보완 탐지, ChatGPT 연결 시 기본값) |
| **비용·일관성** | 코드가 안 바뀌면 이전 응답을 캐시로 재사용합니다. 스캔당 요청 상한(의심 확인 20건, 보완 탐지 10개 파일, 자동 수정안 5묶음)이 있고, 사용량 한도에 걸리면 즉시 멈추고 정적 결과는 그대로 둡니다 |
| **커밋 자동 검사** | "자동 검사에서 ChatGPT 사용"을 켠 경우에만 씁니다(기본 끔) |

### 7. 결과 보기와 내려받기

| 형식 | 용도 | 방법 |
|---|---|---|
| 로컬 대시보드 | 위험 목록·상세·검증된 수정안·검사 범위 | `wescope` |
| 한국어 보고서 (Markdown) | 공유·제출용 | [보고서 내려받기] |
| 결과 JSON | 원본 결과 보관·다른 도구에 넘기기 | [결과 JSON 내려받기] |
| 수정 요청 프롬프트 | Cursor·Claude Code 같은 AI 코딩 도구에 붙여 넣어 고치기 (검증된 diff 포함, 비밀값 원문 없음) | 상세의 [수정 요청 프롬프트 복사] |
| 수정 diff | 직접 적용하기 | 상세의 [diff 복사] |

### 8. 정직한 검사 범위

검사 범위 탭은 We-Scope Top 10의 10개 영역과 OWASP Top 10:2025의 10개 카테고리마다 **위험 발견 / 발견 없음 / 부분 점검 / 해당 없음 / 검사 안 함**을 보여 줍니다. 탐지기가 실패하거나(예: Semgrep 미설치), UTF-8이 아니거나 5MB가 넘어 읽지 못한 파일이 있으면 그 영역을 "발견 없음"으로 보이지 않게 합니다. ChatGPT가 검토한 범위도 따로 표시합니다.

---

## 보안 표준 매핑 / 탐지 패턴

We-Scope는 두 가지 기준으로 발견을 분류합니다.

| 기준 | 역할 | 쓰는 곳 |
|---|---|---|
| **We-Scope Top 10 (WS-01~10)** | 바이브코딩에서 실제로 자주 나는 실수 묶음 | 검사 범위 표, 보고서 목차, 판정 정보 |
| **OWASP Top 10:2025 (A01~A10)** | 업계 표준 분류. 규칙의 CWE를 OWASP 공식 카테고리별 CWE 목록(249개)과 대조해 **자동 부여** | 발견 배지, "OWASP 기준 점검 범위" 표 |
| OWASP Top 10 for LLM Applications 2025 | LLM 영역 보조 분류 | WS-09 발견 배지 |

> OWASP Top 10은 인식 제고 문서이며 준수 체크리스트가 아닙니다. We-Scope는 "OWASP 준수·통과"라고 쓰지 않고 **"OWASP Top 10:2025 분류 기준 점검 범위"** 라고만 씁니다. 매핑할 CWE가 없는 규칙은 "OWASP Top 10 범위 밖"으로 둡니다.

### We-Scope Top 10

| WS | 영역 | 대표 OWASP 2025 | 지금 상태 |
|---|---|---|---|
| WS-01 | 비밀값 노출 | A07, A01 | ✅ 정적 탐지 |
| WS-02 | 인증·인가 누락 | A01, A04, A07 | ✅ 정적 탐지 (Flask·FastAPI·Express) + ChatGPT 보완 |
| WS-03 | 데이터 계층 공개 (Supabase RLS·Firebase rules) | A01 | 🔜 예정 |
| WS-04 | 위험한 의존성 | A03, A08 | 🔜 예정 |
| WS-05 | 입력값 주입 | A05, A01 | ✅ 정적 탐지 (Python·JS·TS) + ChatGPT 파일 간 흐름 |
| WS-06 | 위험한 기본값 | A02, A04, A07, A10 | ✅ 정적 탐지 |
| WS-07 | 웹훅·결제 검증 누락 | A08, A06 | 🤖 ChatGPT 보완 탐지만 (정적 규칙 예정) |
| WS-08 | 남용 방지 부재 | A07 (+LLM10) | 🤖 ChatGPT 보완 탐지만 (정적 규칙 예정) |
| WS-09 | LLM 연동 취약 | A05 (+LLM01·02·05·06) | 🤖 ChatGPT 보완 탐지만 (정적 규칙 예정) |
| WS-10 | AI 에이전트 설정 오염 | A08 | 🔜 예정 |

"예정"인 영역은 검사 범위 탭에 "이 버전에서 아직 검사하지 않는 영역"으로 표시되며, "발견 없음"으로 보이지 않습니다.

### 정적 탐지 규칙 (37개)

규칙마다 실제로 탐지하는 로직을 기준으로 CWE를 하나 정하고, OWASP 카테고리는 그 CWE의 공식 2025 분류를 따릅니다.

| 규칙 ID | 이름 | 기본 심각도 | CWE | OWASP 2025 |
|---|---|---|---|---|
| **WS-01 비밀값 노출** | | | | |
| `secret-env-file` | 환경변수 파일 노출 (Git 상태로 심각도 결정) | CRITICAL | CWE-540 | A01 |
| `secret-credential-file` | 인증 파일 노출 (서비스 계정·개인키·tfstate) | CRITICAL | CWE-540 | A01 |
| `secret-client-bundle` | 클라이언트 번들의 고권한 키 | CRITICAL | CWE-798 | A07 |
| `secret-hardcoded` | 하드코딩된 인증정보 | HIGH | CWE-798 | A07 |
| `secret-frontend-env` | 프론트엔드 환경변수 노출 (`NEXT_PUBLIC_` 등) | HIGH | CWE-200 | A01 |
| `secret-infra-config` | 인프라·CI 설정의 하드코딩된 비밀값 | HIGH | CWE-798 | A07 |
| `secret-dev-tool` | 개발 도구 설정의 인증정보 (`.npmrc`·`.netrc` 등) | HIGH | CWE-798 | A07 |
| `secret-doc` | 문서의 하드코딩된 인증정보 | HIGH | CWE-798 | A07 |
| `secret-data-file` | 데이터·로그 파일 노출 | MEDIUM | CWE-538 | A01 |
| `git-hygiene` | Git 위생 (`.gitignore` 누락·미등록 패턴) | MEDIUM | — | 범위 밖 |
| **WS-02 인증·인가 누락** | | | | |
| `authz-admin-route` | 관리자 경로 권한 확인 누락 | HIGH | CWE-862 | A01 |
| `authz-idor` | IDOR (소유자 확인 없는 객체 조회) | HIGH | CWE-639 | A01 |
| `authz-no-auth-write` | 인증 없는 쓰기 API | HIGH | CWE-306 | A07 |
| `authz-jwt-no-verify` | JWT 서명 미검증 | HIGH | CWE-347 | A04 |
| **WS-05 입력값 주입** | | | | |
| `inject-sql` | SQL 인젝션 (문자열 결합 쿼리) | HIGH | CWE-89 | A05 |
| `inject-command` | 명령어 인젝션 (shell 실행) | HIGH | CWE-78 | A05 |
| `inject-code` | 코드 인젝션 (`eval`·`exec`) | HIGH | CWE-94 | A05 |
| `inject-xss` | XSS (크로스 사이트 스크립팅) | HIGH | CWE-79 | A05 |
| `inject-path` | 경로 조작 (Path Traversal) | HIGH | CWE-22 | A01 |
| `inject-ssrf` | SSRF (서버 측 요청 위조) | HIGH | CWE-918 | A01 |
| `inject-deserialize` | 안전하지 않은 역직렬화 (`pickle`·`yaml.load`) | HIGH | CWE-502 | A08 |
| `inject-xss-template` | XSS (템플릿 자동 이스케이프 해제) | MEDIUM | CWE-79 | A05 |
| `inject-open-redirect` | 오픈 리다이렉트 | MEDIUM | CWE-601 | A01 |
| `inject-upload` | 위험한 파일 업로드 (파일명 미검증) | MEDIUM | CWE-434 | A06 |
| **WS-06 위험한 기본값** | | | | |
| `config-cors-credentials` | CORS 전체 허용 + 자격 증명 허용 | HIGH | CWE-942 | A02 |
| `config-weak-secret` | 약한 서명 키 (`SECRET_KEY`·`JWT_SECRET`) | HIGH | CWE-321 | A04 |
| `config-default-credential` | 기본 계정·비밀번호 | HIGH | CWE-1392 | A07 |
| `config-fail-open` | 실패 시 허용 (fail-open) | HIGH | CWE-636 | A10 |
| `config-debug` | 디버그 모드 활성화 | MEDIUM | CWE-489 | A02 |
| `config-allowed-hosts` | `ALLOWED_HOSTS` 전체 허용 | MEDIUM | — | 범위 밖 |
| `config-cors-wildcard` | CORS 전체 허용 | MEDIUM | CWE-942 | A02 |
| `config-cookie-flags` | 쿠키 보안 속성 누락 (Secure·HttpOnly·SameSite) | MEDIUM | CWE-614 | A02 |
| `config-weak-hash` | 약한 해시로 비밀번호 저장 (MD5·SHA-1) | MEDIUM | CWE-328 | A04 |
| `config-tls-verify-off` | TLS 인증서 검증 해제 | MEDIUM | CWE-295 | A07 |
| `config-error-exposure` | 오류·스택트레이스 노출 | MEDIUM | CWE-209 | A10 |
| `config-swallowed-exception` | 예외 무시 | LOW | CWE-390 | A10 |
| `config-security-todo` | 보안 관련 TODO | INFO | — | 범위 밖 |

### 언어별 탐지 패턴 (Semgrep taint 규칙)

입력값(source)은 Flask `request.*`, Flask·FastAPI 라우트 인자, Express `req.body`·`req.query`·`req.params`·`req.headers`·`req.cookies`입니다.

| 유형 | Python | JavaScript·TypeScript |
|---|---|---|
| SQL 인젝션 | `cursor.execute`·`executemany`·`executescript`, `.raw()`, `QuerySet.extra()`에 문자열 결합 쿼리 | `db.query`·`execute`·`raw`, Prisma `$queryRawUnsafe`·`$executeRawUnsafe` |
| 명령어 인젝션 | `os.system`, `os.popen`, `subprocess.*(shell=True)` | `child_process.exec`·`execSync` |
| 코드 인젝션 | `eval`, `exec` | `eval`, `new Function` |
| 경로 조작 | `open`, `send_file`, `os.remove`·`os.unlink` | `fs.readFile`·`createReadStream`·`writeFile`·`unlink` |
| SSRF | `requests.*`, `httpx.*` | `axios`, `fetch` |
| XSS | `Markup`, `Template`, 응답에 그대로 넣은 HTML | `innerHTML`·`outerHTML`·`insertAdjacentHTML`, React `dangerouslySetInnerHTML` |
| 템플릿 이스케이프 해제 | Jinja `\|safe`, `{% autoescape false %}` | Vue `v-html`, Svelte `{@html}`·`set:html` |
| 오픈 리다이렉트 | `redirect(사용자값)` | `res.redirect(사용자값)` |
| 위험한 업로드 | `secure_filename` 없이 원래 파일명으로 저장 | multer의 `originalname`을 그대로 저장 경로로 |
| 역직렬화 | `pickle`·`marshal`·`dill`·`jsonpickle`, `yaml.load`(SafeLoader 없이) | — |
| JWT 서명 미검증 | `jwt.decode(verify_signature=False)`, `algorithms=["none"]` | `jwt.decode`로만 읽기, `algorithms: ['none']` |
| 설정 (JS) | — | `cors()`·`origin: '*'`, `credentials: true`, 쿠키 `httpOnly`·`secure` 끔, 하드코딩된 세션·JWT 비밀값 |

이미 막힌 경로는 잡지 않습니다: 파라미터 바인딩, `shlex.quote`, `secure_filename`·`uuid` 파일명, `os.path.basename`, 이스케이프 함수, 대문자 허용 목록 딕셔너리(`ALLOWED_HOSTS[key]`) 등.

### ChatGPT 보완 탐지 유형 (18개)

ChatGPT는 아래 정해진 유형에서만 고를 수 있습니다. 유형마다 CWE가 정해져 있어 OWASP 분류는 엔진이 계산합니다.

| 영역 | 유형 (CWE) |
|---|---|
| WS-02 인증·인가 | 권한 확인 누락 (862), IDOR (639), 파일 접근 권한 누락 (639), 클라이언트가 보낸 신원 신뢰 (602), 대량 할당 (915), 약한 재설정·인증 토큰 (640), 인가 누락 — 정적 규칙이 없는 언어 (862) |
| WS-05 입력값 주입 | 파일 간 SQL 인젝션 (89), 파일 간 명령 인젝션 (78), 파일 간 XSS (79), 파일 간 경로 조작 (22), 주입 — 정적 규칙이 없는 언어 (74) |
| WS-06 위험한 기본값 | 세션 고정 (384) |
| WS-07 웹훅·결제 | 가격 변조 (602), 상태 전이 건너뛰기 (841), 경쟁 조건 이중 처리 (362) |
| WS-08 남용 방지 | 계정 열거 (204) |
| WS-09 LLM 연동 | LLM 과도한 권한 (LLM06) |

### 매핑 범위

- 정적 규칙 37개 + ChatGPT 유형 18개, **고유 CWE 35종**
- OWASP Top 10:2025 중 **8개 카테고리**(A01·A02·A04·A05·A06·A07·A08·A10) 점검
- A03 Software Supply Chain Failures는 WS-04(예정)에서, A09 Security Logging & Alerting Failures는 정적 분석으로 판단하기 어려워 아직 점검하지 않습니다

### 심각도와 신뢰도

| 심각도 | 기준 | 예시 |
|---|---|---|
| **CRITICAL** | 즉시 악용 가능, 데이터 전체·금전 피해로 직결 | 커밋된 `.env`·클라우드 인증 파일, 클라이언트에 노출된 `service_role` 키 |
| **HIGH** | 공격 경로가 명확한 취약점 | SQL 인젝션, 관리자 API 인가 누락, 하드코딩된 API 키 |
| **MEDIUM** | 조건이 맞으면 위험, 모범 사례 위반 | `debug=True`, CORS `*`, 쿠키 속성 누락 |
| **LOW** | 방어 수준 저하 | 예외 무시 |
| **INFO** | 참고 | 보안 관련 TODO |

| 신뢰도 | 의미 |
|---|---|
| **Likely** | 같은 함수 안에서 입력 → 위험 지점 흐름을 직접 확인했습니다 |
| **Potential** | 가드·설정이 **없는 것으로 보인다**는 추정입니다. 상위 미들웨어 등은 확인하지 못했습니다 |

정적 분석 결과는 "확정(Confirmed)"으로 표시하지 않습니다. ChatGPT가 확인한 발견만 Potential → Likely로 올라가고 `AI 확인` 표시가 붙습니다.

---

## 기존 도구와의 차이점

We-Scope는 Semgrep·Bandit보다 더 깊은 SAST를 목표로 하지 않습니다. Semgrep은 We-Scope 안에서 엔진으로 쓰입니다. We-Scope가 다르게 겨냥하는 지점은 다음과 같습니다.

| | 일반 정적 분석기 | 시크릿 스캐너 | AI에게 직접 질문 | **We-Scope** |
|---|---|---|---|---|
| 검사 기준 | 규칙 (영어) | 시크릿 패턴 | 매번 다름 | 규칙 + We-Scope Top 10 + OWASP 2025 |
| 결과 설명 | 짧은 경고 | 짧은 경고 | 자연어 (근거 불확실) | 무엇·왜·어떻게 (한국어) + 수정 예시 |
| 수정안 | 없음 | 없음 | 있으나 검증 안 됨 | 내 코드 기준 diff + **적용·문법·재검사로 검증** |
| 업무 로직 취약점 (IDOR·금액 변조 등) | 거의 못 찾음 | 못 찾음 | 찾지만 근거 불확실 | ChatGPT가 찾고 **인용 코드를 실제 코드와 대조**해 확인된 것만 |
| 비밀값 판정 | — | 파일 내용 기준 | — | **Git 상태**(커밋됨·커밋 안 함·ignore됨)로 심각도 결정 |
| 검사하지 못한 영역 | 표시 안 함 | 표시 안 함 | 알 수 없음 | "검사 안 함·부분 점검"으로 표시 |
| 변화 추적 | 별도 설정 | 일부 | 없음 | NEW·FIXED 자동 표시, 커밋할 때마다 자동 검사 |
| 사용 방식 | CLI·CI | CLI·CI | 채팅 | `wescope` 한 단어 → 로컬 대시보드 |
| 코드 전송 | 없음 | 없음 | 붙여 넣은 만큼 | 정적 분석은 없음. ChatGPT 연결 시 위험 코드·관련 파일만 (비밀값 자리표시, `.env` 제외) |
| 비용 | 무료 | 무료 | 구독 | 무료 (AI는 본인 ChatGPT 구독) |

한계도 분명합니다. We-Scope는 실행 중인 서비스를 공격해 보는 동적 진단을 하지 않으며, 정적 분석 결과로 "안전"을 보증하지 않습니다. 지원하는 언어·프레임워크 밖의 코드는 ChatGPT 보완 탐지로만 일부를 봅니다([지원 범위와 한계](#지원-범위와-한계)).

---

## 사용법

### 필요한 것

- Python **3.11 이상**
- Git (Git 상태 판정, GitHub 주소 clone, 커밋 자동 검사에 사용)
- 최신 브라우저 (데스크톱)
- (선택) ChatGPT 구독 — 수정안 생성·의심 확인·보완 탐지를 쓸 때

Semgrep과 tree-sitter는 We-Scope를 설치할 때 함께 설치됩니다. Semgrep 실행에 실패해도 검사는 끝까지 진행되고, 입력값 주입 영역만 "건너뜀"으로 표시됩니다.

### 설치 (처음 한 번)

```bash
git clone https://github.com/jubin0615/WeScope.git
cd WeScope
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -e .
```

> PyPI 배포 후에는 `pipx install wescope` 한 줄로 설치할 수 있게 할 예정입니다.

### 실행 (이후 매번)

```bash
wescope
```

터미널에는 대시보드 주소와 "종료하려면 Ctrl+C를 누르세요."만 표시되고, 브라우저가 자동으로 열립니다. 설치 이후에는 이 명령 외에 터미널 입력이 필요하지 않습니다. 별도의 CLI 검사 명령이나 옵션은 없습니다.

### 대시보드에서 하는 일

1. **프로젝트 연결** — 시작 화면에 프로젝트 폴더 경로(예: `C:\Users\me\my-app`) 또는 GitHub 주소(`https://github.com/소유자/저장소`)를 입력하고 [검사 시작]을 누릅니다.
2. **결과 확인** — 왼쪽 위험 목록은 같은 규칙끼리 묶여 심각도 순으로 정렬됩니다. 행을 누르면 오른쪽 상세에 설명·위치·판정 정보(WS·OWASP·CWE·신뢰도)·수정 방법이 보입니다.
3. **거르기** — 요약 줄의 심각도 숫자(`HIGH 3`)를 누르면 그 심각도만 봅니다. 보기 탭에서 전체 · NEW · FIXED · AI · 오탐 표시 · 검사 범위를 오갑니다.
4. **고치기** — [수정 요청 프롬프트 복사]로 AI 코딩 도구에 붙여 넣거나, ChatGPT를 연결했다면 [수정안 만들기]로 검증된 diff를 받아 [diff 복사]로 직접 적용합니다. 마음에 들지 않으면 [다른 수정안]을 누릅니다.
5. **다시 보기** — 고친 뒤 [다시 스캔]을 누르면 FIXED로 표시됩니다. 로컬 Git 폴더라면 커밋만 해도 자동으로 다시 검사합니다.
6. **내려받기** — [보고서 내려받기]로 한국어 Markdown 보고서를, [결과 JSON 내려받기]로 원본 결과를 받습니다.

### 설정 창 (⚙)

| 탭 | 내용 |
|---|---|
| 이 프로젝트 | 제외할 파일·폴더(`.gitignore` 문법), 꺼 둔 규칙, 커밋 자동 검사 켜기·끄기 |
| ChatGPT | 연결 상태·로그아웃, 분석 수준(끔/기본/심층), 자동 검사에서 ChatGPT 사용, 보내는 것/보내지 않는 것 표 |
| 화면 | 테마 (시스템 / 라이트 / 다크) |
| 데이터 | 프로젝트 연결 해제 (결과와 이력이 지워지고, 원본 폴더는 그대로입니다) |

### 검사에서 빼기

다음 경로는 자동으로 제외합니다: `node_modules`, `.git`, `.venv`, `venv`, `build`, `dist`, `coverage`, `__pycache__`, `.next`, `.nuxt`, `.output`, `vendor`, `target`, `.gradle`, `.tox`, `.mypy_cache`, `.pytest_cache`, `*.min.js`, 5MB를 넘는 파일.

더 빼고 싶으면 프로젝트 루트에 `.wescopeignore`(`.gitignore` 문법)를 두거나, 설정 창 > 이 프로젝트 > 제외할 파일·폴더에 적습니다. 둘이 겹치면 대시보드 설정이 우선합니다.

### 데이터 저장 위치

모든 데이터는 사용자 PC의 `~/.wescope/`에만 저장됩니다.

| 경로 | 내용 |
|---|---|
| `history.sqlite` | 연결한 프로젝트·검사 이력·발견 이력·오탐 표시 (코드 원문 없음) |
| `results/<프로젝트>/<검사>.json` | 검사 결과 원본 (비밀값은 앞 4글자만 남기고 가림) |
| `repos/` | GitHub 주소로 연결한 프로젝트의 We-Scope 전용 clone |
| `config.toml` | 전역 설정 (테마·분석 수준·자동 검사 AI) |
| `auth.json` | ChatGPT 토큰 (Windows는 DPAPI 암호화, 그 밖은 권한 600) |
| `ai-cache/` | ChatGPT 응답 캐시 (코드 해시 기준) |

---

## 동작 원리

```
터미널에 wescope → 대시보드 [다시 스캔] / git commit(hook)
        │
        ▼
  Collector   현재 파일을 임시 스냅샷으로 복사(GitHub는 최신 커밋), Git 상태 기록,
              민감 파일은 경로·종류만, 비밀값 레지스트리(이후 모든 출력의 마스킹 기준)
        │
        ▼
  Analyzers   비밀값 · 라우트/인가 · Python 설정(AST) · 위험한 기본값 · Semgrep taint
              — 탐지기 하나가 실패해도 나머지는 계속, 실패는 검사 범위에 표시
        │
        ▼
  Engine      정규화 · CWE → OWASP 분류 · 지문 · 직전 검사와 비교(NEW/FIXED)
        │
        ▼
  ChatGPT     (연결했을 때) 보완 탐지 → 의심 발견 확인 → 수정안 생성
              → 임시 사본에 적용 · 문법 검사 · 같은 탐지기로 재검사
        │
        ▼
  Aggregate   오탐·꺼 둔 규칙 반영 · 검사 범위 · 위험 점수 · 요약 → 결과 JSON · SQLite
        │
        ▼
  Dashboard   위험 목록 + 상세 · 검증된 diff · 수정 요청 프롬프트 · 보고서
```

- **결정성**: 같은 코드를 두 번 검사하면 발견·검사 범위·요약이 같습니다. ChatGPT 결과도 코드 해시로 캐시해 검사 간 비교가 의미를 가집니다.
- **분류는 엔진이**: OWASP 코드는 CWE에서 자동 계산됩니다. ChatGPT는 분류를 바꾸거나 정적 발견을 지울 수 없고, AI 발견의 심각도는 유형마다 정해진 상한을 넘지 못합니다.

더 자세한 내용은 [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md)와 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)를 참고하세요.

---

## 보안·개인정보 원칙

| 원칙 | 구현 |
|---|---|
| 읽기 전용 | 검사 대상 폴더를 수정하지 않습니다. 현재 파일을 임시 폴더로 복사해 읽고, 검사가 끝나면 지웁니다. 수정안도 diff로만 건네고 직접 적용하지 않습니다 |
| 로컬 전용 서버 | 대시보드는 `127.0.0.1`에만 바인딩되고, 실행마다 새로 발급하는 접속 티켓(HttpOnly·SameSite=Strict 쿠키)이 있어야 열립니다. Host·Origin을 확인해 DNS 리바인딩과 다른 사이트의 요청을 막습니다 |
| 비밀값 마스킹 | 결과 JSON·SQLite·보고서·프롬프트·ChatGPT 요청 어디에도 원문 비밀값을 남기지 않습니다. 화면에는 앞 4글자 + `••••`만 보입니다 |
| 민감 파일 미열람 | `.env`·키·인증 파일·데이터 파일은 경로와 종류만 기록하고, 임시 스냅샷에도 복사하지 않습니다 |
| ChatGPT 전송 범위 | 위험이 있는 함수와 관련 정의, 보완 탐지 대상으로 고른 파일, 프레임워크 정보만 보냅니다. 비밀값은 `«WS_SECRET_n»` 자리표시로 바꿉니다. 저장소 전체와 `.env`·키 파일은 보내지 않고, 커밋 자동 검사에서는 동의 전까지 쓰지 않습니다 |
| 코드는 데이터 | 검사한 코드·문서 속 문장을 We-Scope나 ChatGPT에 대한 지시로 취급하지 않습니다. 지시문처럼 보이는 텍스트가 있는 파일은 표시하고, 그 파일에 대한 오탐 제안은 무시합니다 |
| 사용자가 결정 | HIGH 이상 발견을 사용자 확인 없이 오탐 처리하지 않습니다. ChatGPT는 오탐을 "제안"만 합니다 |
| 허가된 대상만 | 본인 소유이거나 검사를 허가받은 저장소만 검사하세요. We-Scope에는 동적 공격 기능이 없습니다 |

---

## 지원 범위와 한계

| 구분 | 지원 |
|---|---|
| 언어 (정적 주입 탐지) | Python, JavaScript, TypeScript |
| 프레임워크 (라우트·인가) | Flask, FastAPI, Express |
| 비밀값·민감 파일·Git 위생 | 언어와 무관하게 모든 텍스트 파일 |
| 그 밖의 언어 | ChatGPT 보완 탐지("정적 규칙이 없는 언어" 유형)로만 일부 검토 |
| 운영체제 | Windows에서 개발·테스트합니다. macOS·Linux도 코드상 지원하지만 아직 직접 검증하지 않았습니다 |
| 화면 | 데스크톱 브라우저, 한국어 |

- Django 라우트·입력값 지원을 개발하고 있습니다. 그전까지 Django 앱은 비밀값·설정 위주로만 점검됩니다.
- Java(Spring), Next.js 라우트, Supabase·Firebase 규칙, 의존성 점검은 아직 지원하지 않습니다.
- 정적 분석은 같은 함수 안의 흐름을 기준으로 합니다. 파일을 넘나드는 흐름은 ChatGPT 보완 탐지가 일부를 봅니다.
- 범위 밖: 실행 중인 서비스에 대한 공격·침투, CLI 검사 명령·CI 연동, 중앙 서버·회원 관리, 수정안 자동 적용, OpenAI 외 LLM 연동.

---

## 기술 스택

### 분석 엔진

| 구분 | 선택 | 이유 |
|---|---|---|
| 언어 | Python 3.11+ | 보안·정적 분석 생태계, AST 내장 |
| 주입 패턴 탐지 | Semgrep (자체 규칙만, 오프라인) | 다언어 taint 분석, 규칙을 YAML로 관리. 레지스트리 규칙·원격 통계 미사용 |
| Python 구조 분석 | `ast` (내장) | 라우트·설정·함수 범위 추출 |
| 시크릿·파일 탐지 | 정규표현식 + 파일명 규칙 | 의존성 없음, 빠름, 규칙이 투명함 |
| Git | `git` CLI | 추적 여부 확인, clone·fetch, post-commit hook |
| 제외 규칙 | `pathspec` | `.gitignore` 문법 호환 |
| 규칙 메타 | PyYAML | 규칙 설명·CWE·OWASP 카탈로그 |

### 대시보드

| 구분 | 선택 | 이유 |
|---|---|---|
| 백엔드 | FastAPI + Uvicorn, `127.0.0.1` 바인딩 | 로컬 전용, 가벼움 |
| 프론트엔드 | 빌드 없는 HTML + CSS + JavaScript (패키지에 포함) | `pip install`만으로 동작 |
| 진행 상황 | Server-Sent Events | 단계별 진행 표시 |
| 저장소 | SQLite (WAL) + 결과 JSON | 서버 없음, 파일 하나 |
| 디자인 | Pretendard 번들, 라이트·다크 테마 | 한국어 가독성 |

### ChatGPT 분석

| 구분 | 선택 |
|---|---|
| 인증 | Sign in with ChatGPT (OAuth PKCE, 로컬 토큰 저장) |
| 호출 | OpenAI Responses API (스트리밍, `store: false`), 응답은 JSON 형식으로 검증 |
| 추론 강도 | 수정안·보완 탐지는 높게, 의심 확인은 중간 |
| 수정안 검증 | `git apply`(임시 사본), Python `ast`, tree-sitter(JS·TS), We-Scope 탐지기 재실행 |
| 캐시 | `~/.wescope/ai-cache/` (코드 해시 기준) |
| HTTP | 표준 라이브러리 (추가 의존성 없음) |

### 품질

| 구분 | 선택 |
|---|---|
| 테스트 | pytest (Python 169개), Node 내장 `node:test` (대시보드 UI 15개) |
| 테스트용 앱 | 취약 표본(`vuln_flask`·`vuln_express`·`vuln_logic`·`secrets_zoo`)과 같은 패턴의 안전 표본(`clean_app`) |
| 불변식 테스트 | 원본 폴더 불변 · 결과 어디에도 비밀값 원문 없음 · 같은 코드 같은 결과 · 탐지기 실패 격리 · 안전 표본 오탐 0 |

---

## 개발·테스트

```bash
pip install -e ".[dev]"

# Python 테스트
python -m pytest -q

# 대시보드 UI 테스트 (Node.js 18 이상)
node --test tests/web/test_dashboard_ui.cjs
```

- 테스트용 앱은 `tests/fixtures/`에 있고, 심은 취약점마다 `# expect: 규칙ID` 주석으로 기대 발견을 적습니다. 테스트는 이 주석과 실제 발견이 정확히 같은지 확인합니다.
- 표본 속 가짜 비밀값은 `{{FAKE:종류}}` 표시로 두고 테스트할 때만 값으로 바꿔, 저장소에 비밀값처럼 보이는 문자열이 남지 않게 합니다.
- 대시보드는 샘플 결과 JSON(`tests/fixtures/results/*.json`)만으로도 개발할 수 있습니다. 결과 JSON과 API 형식은 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §4·§7에 고정돼 있고 `tests/test_contract.py`가 지킵니다.
- 계층 사이 import 방향(엔진은 저장소·서버를 모르고, ChatGPT 분석은 탐지기를 모르는 식)은 `tests/test_layers.py`가 확인합니다.

---

## 로드맵

- [x] **M0 문서·뼈대** — 문서 세트, 데이터 모델, 테스트용 취약 앱, 불변식 테스트
- [x] **M1 엔진 + 첫 대시보드** — WS-01·02·05·06, OWASP 자동 분류, 한국어 설명, `wescope` 실행기, 시작 화면, 위험 목록·상세, 수정 요청 프롬프트, 보고서 내려받기
- [x] **M2 이력·자동 검사** — SQLite 이력, NEW/FIXED, 커밋 자동 검사, 오탐 표시, 여러 프로젝트, 설정 창
- [ ] **M3 ChatGPT 분석 + 바이브코딩 특화**
  - [x] Sign in with ChatGPT, 수정안 생성·로컬 검증, 의심 발견 확인, 보완 탐지, 입출력 가드, 캐시
  - [ ] Django 라우트·입력값 지원 (진행 중)
  - [ ] 체인 상관 분석 (여러 발견을 하나의 공격 경로로)
  - [ ] WS-03 데이터 계층 · WS-07 웹훅·결제 · WS-08 남용 방지 · WS-09 LLM 연동 정적 규칙
  - [ ] 설명 구체화 (규칙 설명을 내 코드 기준 문장으로)
- [ ] **M4 확장** — WS-04 의존성 · WS-10 에이전트 설정, Next.js 라우트, Java(Spring), HTML 보고서
- [ ] 외부 취약 앱(OWASP Juice Shop·PyGoat 등)으로 탐지율·수정안 검증률 측정 (`bench/`)
- [ ] PyPI 배포 (`pipx install wescope`)

---

## 문서

| 문서 | 내용 |
|---|---|
| [docs/PRD.md](docs/PRD.md) | 제품 요구사항: 문제 정의, 기능, 분류 기준, 마일스톤, 성공 지표 |
| [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) | 검사 한 번이 단계별로 어떻게 진행되는지 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 모듈 구조, 결과 JSON 형식, API |
| [docs/RULES.md](docs/RULES.md) | 규칙별 탐지 조건·심각도·신뢰도 |
| [docs/AI.md](docs/AI.md) | ChatGPT 분석 설계: 역할, 전송 범위, 가드, 검증 |
| [docs/DIRECTORY_STRUCTURE.md](docs/DIRECTORY_STRUCTURE.md) | 폴더 구조 |

---

## 라이선스

MIT License
