# We-Scope — 프로젝트 디렉터리 구조

> 패키지는 `src/wescope/`, 명령어는 `wescope`이다.
> 저장소: https://github.com/jubin0615/WeScope (v1, 새로 시작). 기존 프로토타입(v0.2)은 https://github.com/jubin0615/WE_MEET 에 그대로 두고 참고만 한다.
> 맨 아래 §4에 v0.2 파일이 v1의 어디로 옮겨 가는지 정리했다.

```
WeScope/
│
├── pyproject.toml                # 패키지 메타데이터, 의존성, 명령어(wescope) 등록
├── README.md                     # 설치·실행·첫 검사 안내
├── LICENSE                       # MIT
├── CHANGELOG.md                  # 버전별 변경 사항
├── .gitignore
│
├── docs/
│   ├── PRD.md                    # 무엇을 왜 만드는가
│   ├── ARCHITECTURE.md           # 구조와 데이터 모델
│   ├── HOW_IT_WORKS.md           # 단계별 동작 (코드 수준)
│   ├── AI.md                     # ChatGPT 분석 (보완 탐지·수정안 생성·검증)
│   ├── DASHBOARD.md              # 대시보드 화면 설계
│   ├── RULES.md                  # 탐지 규칙 카탈로그 (WS·CWE·OWASP)
│   ├── DIRECTORY_STRUCTURE.md    # 이 문서
│   └── PORTFOLIO.md              # 발표·포트폴리오용 요약
│
├── src/
│   └── wescope/
│       ├── __init__.py           # 버전
│       ├── __main__.py           # `wescope` 명령 = 서버 시작 + 브라우저 열기 (인자 없음)
│       ├── config.py             # 설정 병합 (프로젝트 설정 > 전역 설정 > 기본값)
│       ├── paths.py              # ~/.wescope/ 하위 경로, 패키지 데이터 경로
│       ├── scan.py               # run_scan(): 파이프라인 조립 (작업 큐·hook·테스트가 호출)
│       │
│       ├── collector/
│       │   ├── __init__.py
│       │   ├── snapshot.py       # 폴더 현재 파일 복사 · GitHub clone/fetch·최신 커밋 export, 임시 폴더 관리
│       │   ├── gitstate.py       # 파일별 Git 상태 (커밋됨 / 커밋 안 함 / ignore됨)
│       │   ├── files.py          # Track A·B: 텍스트 판별, 제외 디렉터리, 크기·인코딩·링크 보호
│       │   ├── ignore.py         # Track C: .gitignore · .wescopeignore (pathspec)
│       │   ├── sensitive.py      # Track D: .env·키·인증 파일 메타 (내용 미열람)
│       │   ├── inventory.py      # AppProfile: 언어·프레임워크·매니페스트·SDK·적용성
│       │   └── context.py        # ScanContext, SecretRegistry, 지연 로딩 캐시
│       │
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── base.py           # Analyzer 추상 클래스, AnalyzerResult, RawHit
│       │   ├── registry.py       # 등록 순서 = 실행 순서
│       │   │
│       │   ├── secrets/          # WS-01
│       │   │   ├── __init__.py   # SecretsAnalyzer (아래 모듈 조합)
│       │   │   ├── files.py      #   secret-env-file · secret-credential-file · secret-data-file
│       │   │   ├── hardcoded.py  #   secret-hardcoded · secret-doc
│       │   │   ├── frontend.py   #   secret-frontend-env · secret-client-bundle
│       │   │   ├── infra.py      #   secret-infra-config · secret-dev-tool
│       │   │   ├── git_hygiene.py#   git-hygiene
│       │   │   ├── patterns.py   #   공급자 키 정규식, 인증정보 변수명
│       │   │   └── _filters.py   #   자리표시 값·환경변수 참조·테스트 파일 오탐 필터
│       │   │
│       │   ├── semgrep.py        # WS-05 외: rules/semgrep 실행, JSON → RawHit
│       │   │
│       │   ├── routes/           # WS-02 + 라우트 인벤토리
│       │   │   ├── __init__.py   # RoutesAnalyzer: authz-* 판정
│       │   │   ├── model.py      #   Route, 가드 단서, 함수 범위
│       │   │   ├── flask.py      #   @app.route, Blueprint
│       │   │   ├── fastapi.py    #   APIRouter, Depends
│       │   │   ├── django.py     #   urls.py path·include → view 함수·클래스, 가드 데코레이터·Mixin
│       │   │   ├── express.py    #   app.get/router.post, 미들웨어 인자
│       │   │   └── nextjs.py     #   (M4) app/**/route.ts, Server Action
│       │   │
│       │   ├── config.py         # WS-06: Python AST 설정 (debug·CORS·쿠키·서명키)
│       │   ├── insecure_defaults.py # WS-06: TLS·기본 계정·fail-open·약한 해시·보안 TODO
│       │   ├── baas.py           # WS-03 (M3): Supabase SQL·Firebase rules
│       │   ├── webhooks.py       # WS-07 (M3)
│       │   ├── abuse.py          # WS-08 (M3)
│       │   ├── llm.py            # WS-09 (M3): 클라이언트 키 등 Semgrep 밖 규칙
│       │   ├── dependencies.py   # WS-04 (M4)
│       │   ├── agent.py          # WS-10 (M4)
│       │   └── java/             # (M4) 기존 Java 흐름·Spring 정책 이식
│       │       ├── __init__.py
│       │       ├── flow.py       #   inject-java-sql-flow
│       │       └── spring.py     #   authz-spring-policy
│       │
│       ├── engine/
│       │   ├── __init__.py
│       │   ├── runner.py         # run_all(): 고정 순서 실행, 타임아웃, 실패 격리, strict
│       │   ├── normalize.py      # 규칙 메타 결합, 지문, 중복 병합, 정렬
│       │   ├── correlate.py      # 체인 발견 (M3)
│       │   ├── compare.py        # new / existing / fixed / unknown
│       │   ├── coverage.py       # WS·OWASP 검사 범위 상태
│       │   ├── score.py          # 위험 점수
│       │   └── aggregate.py      # 사용자 표시 반영, 요약 → ScanResult
│       │
│       ├── taxonomy/
│       │   ├── __init__.py
│       │   ├── catalog.py        # 규칙 메타 로더 (rules/catalog + semgrep 메타)
│       │   └── owasp.py          # CWE → OWASP Top 10:2025, LLM·Agentic 코드 이름
│       │
│       ├── rules/                # 패키지 데이터 (pip 설치 시 함께 배포)
│       │   ├── catalog/
│       │   │   ├── ws-top10.yml          # WS-01~10 이름·설명·관련 OWASP
│       │   │   ├── owasp-top10-2025.yml  # A01~A10, 공식 "List of Mapped CWEs" 전체
│       │   │   ├── owasp-ai.yml          # LLM01~10(2025), ASI01~10(2026)
│       │   │   ├── secrets.yml           # 비 Semgrep 규칙 메타 (WS-01)
│       │   │   ├── authz.yml             # (WS-02)
│       │   │   ├── config.yml            # (WS-06)
│       │   │   └── ...                   # 영역별 1파일
│       │   └── semgrep/
│       │       ├── inject-sql.yml
│       │       ├── inject-code.yml
│       │       ├── inject-command.yml
│       │       ├── inject-xss.yml
│       │       ├── inject-xss-template.yml
│       │       ├── inject-path.yml
│       │       ├── inject-ssrf.yml
│       │       ├── inject-deserialize.yml
│       │       ├── inject-upload.yml
│       │       ├── inject-open-redirect.yml
│       │       ├── authz-jwt-no-verify.yml
│       │       ├── config-cors.yml        # JS 쪽 CORS·쿠키·오류 노출
│       │       └── llm-flows.yml          # (M3) llm-prompt-injection · llm-output-sink
│       │
│       ├── llm/                  # ChatGPT 분석 (M3) — AI.md 기준
│       │   ├── __init__.py
│       │   ├── auth.py           # Sign in with ChatGPT, 토큰 저장·갱신
│       │   ├── client.py         # Responses API 호출, JSON 스키마 응답, 429·403 처리, 동시 요청 제한
│       │   ├── guards.py         # 보내기 전(민감 파일 제외·비밀값 자리표시·지시문 표시), 받은 뒤(분류 불변·하향 제한)
│       │   ├── context.py        # 맥락 수집: 수정안용·확인용·보완 탐지용 패키지
│       │   ├── review_targets.py # 보완 탐지 대상 선정 (인증·인가·결제·대량 할당·파일 간 흐름·LLM·미지원 언어)
│       │   ├── review.py         # 의심 발견 확인 + 보완 탐지 + 환각 방지 검증
│       │   ├── fixer.py          # 수정안 생성, 실패 시 재요청
│       │   ├── verify.py         # 임시 사본 적용 · 문법 검사 · 탐지기 재실행 → verified / partial / failed
│       │   ├── prompts.py        # 작업별 지시문·응답 스키마 (프롬프트 버전 관리)
│       │   ├── budget.py         # 스캔당 요청 상한·우선순위
│       │   └── cache.py          # ~/.wescope/ai-cache (코드 해시 기준)
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── finding.py        # Severity, Confidence, Location, Triage, Finding
│       │   └── scan_result.py    # ScanResult, CoverageRow, AnalyzerStatus, JSON 입출력
│       │
│       ├── store/
│       │   ├── __init__.py
│       │   ├── results.py        # 결과 JSON 저장·조회
│       │   └── history.py        # SQLite 스키마·마이그레이션·이력 조회
│       │
│       ├── report/
│       │   ├── __init__.py
│       │   ├── markdown.py       # 한국어 보고서 (Markdown) — 내려받기 요청 시 생성
│       │   ├── html.py           # (M4) HTML 보고서
│       │   └── wording.py        # 심각도·상태 한국어 표기, 공통 문구
│       │
│       ├── server/               # 로컬 대시보드 서버 (M1)
│       │   ├── __init__.py
│       │   ├── app.py            # FastAPI 앱, 127.0.0.1 바인딩, 접속 티켓→쿠키, Host·Origin 검사
│       │   ├── state.py          # ~/.wescope/server.json (포트·PID·티켓), 중복 실행 감지
│       │   ├── api_state.py      # 첫 화면 판단 (/api/state)
│       │   ├── api_repos.py      # 프로젝트 연결·해제·clone·hook 설치, 프로젝트 설정
│       │   ├── api_scans.py      # 스캔 시작·진행(SSE)·결과·내려받기
│       │   ├── api_ignores.py    # 오탐 표시·되돌리기 (M2)
│       │   ├── api_settings.py   # 전역 설정, ChatGPT 로그인 상태
│       │   └── jobs.py           # 작업 큐 (한 번에 1개, 프로젝트별 디바운스)
│       │
│       ├── hook.py               # post-commit hook 설치·해제 + `python -m wescope.hook` 내부 진입점
│       │                         #   (서버 있으면 검사 요청, 없으면 직접 검사) — 사용자 명령 아님, 사용자 알림 없음
│       │
│       └── web/                  # 빌드 없는 정적 프론트엔드 (패키지 데이터) — DASHBOARD.md 기준
│           ├── index.html
│           ├── app.js            # 상태 관리, API·SSE, 화면 조립
│           ├── dom.js            # h() 화면 조각 도우미, 심각도 목록
│           ├── wording.js        # 상태 코드 한국어 표기 (report/wording.py와 같은 문자열, 테스트로 확인)
│           ├── components/
│           │   ├── start.js      #   시작 화면: 입력 2개(폴더 경로 / GitHub 주소), 프로젝트 추가 창
│           │   ├── topbar.js     #   로고 · 프로젝트 선택 · 상태 문장·진행 표시 · ChatGPT 상태 · ⚙ · [다시 스캔]
│           │   ├── summary.js    #   요약 줄 (심각도 색 라벨 개수 · NEW/FIXED · 위험 점수 · 보고서 ↓)
│           │   ├── tabs.js       #   보기 탭 (전체·NEW·FIXED·AI·오탐 표시·검사 범위)
│           │   ├── list.js       #   왼쪽 위험 목록: 묶기·정렬·선택 유지
│           │   ├── detail.js     #   오른쪽 상세: 수정안(diff 보기 포함)·설명·위치·판정 정보 탭, 하단 버튼(수정안 만들기·오탐)
│           │   ├── prompt.js     #   수정 요청 프롬프트 조립 (검증된 diff 포함, 비밀값 원문 없음)
│           │   ├── coverage.js   #   검사 범위 탭 (WS·OWASP·ChatGPT 검토 범위)
│           │   └── settings.js   #   설정 창 (화면 가운데, 폭 640px): 이 프로젝트 · ChatGPT · 화면 · 데이터
│           ├── theme.js          # 첫 화면 테마 깜빡임 방지
│           ├── app.css           # 디자인 토큰 (본문 · --chrome-* 상단 바 · --sev-* 심각도 글자색)
│           └── fonts/            # Pretendard 가변 번들
│
├── tests/
│   ├── conftest.py               # fixture 저장소를 임시 Git 저장소로 만드는 헬퍼
│   ├── test_launcher.py          # wescope 실행: server.json, 중복 실행 시 재사용, 종료 시 정리
│   ├── test_collector/
│   │   ├── test_snapshot.py      # 현재 파일 반영, GitHub 최신 커밋, 원본 불변
│   │   ├── test_gitstate.py      # 커밋됨 / 커밋 안 함 / ignore됨 판정
│   │   ├── test_files.py
│   │   └── test_sensitive.py
│   ├── test_analyzers/
│   │   ├── test_secrets.py
│   │   ├── test_routes.py
│   │   ├── test_config.py
│   │   └── ...                   # Analyzer당 1파일: 양성·음성·빈 폴더
│   ├── test_rules_semgrep.py     # rules/semgrep 각 규칙의 취약·안전 표본
│   ├── test_engine/
│   │   ├── test_normalize.py     # 지문 안정성, OWASP 분류
│   │   ├── test_compare.py
│   │   ├── test_coverage.py
│   │   └── test_score.py
│   ├── test_taxonomy.py          # 한 CWE = 한 OWASP, 모든 규칙 메타 완비
│   ├── test_llm/
│   │   ├── test_guards.py        # 민감 파일 미전송, 비밀값 자리표시, 분류 불변, HIGH 자동 오탐 금지
│   │   ├── test_review.py        # 인용 불일치 AI 발견 폐기, 정적 발견과 병합
│   │   ├── test_verify.py        # 적용 실패·문법 오류·문제 남음 → verified 아님, 원본 불변
│   │   ├── test_cache.py         # 같은 코드 → 요청 없이 같은 결과
│   │   └── fake_chatgpt.py       # 정해진 응답을 돌려주는 가짜 클라이언트 (테스트에 실제 구독 불필요)
│   ├── test_server.py            # 로컬 전용 접근, 티켓, 작업 큐, export
│   ├── test_hook.py              # 서버 있음/없음 두 경로, 기존 hook 보존
│   ├── web/
│   │   └── test_dashboard_ui.cjs # 묶기 · 정렬 · 탭 필터 · 선택 유지 · 프롬프트에 비밀값 없음
│   ├── test_invariants.py        # 원본 불변 · canary 비밀값 · 결정성 · 실패 격리
│   │
│   └── fixtures/
│       ├── clean_app/            # 같은 기능을 안전하게 구현한 앱 (오탐 0 기준)
│       ├── vuln_flask/           # WS-01·02·05·06 취약점을 심은 Flask 앱
│       ├── vuln_express/         # 같은 취약점의 Express 앱
│       ├── vuln_django/          # 같은 취약점의 Django 앱 (urls.py·함수/클래스 view·DRF·settings)
│       ├── vuln_next/            # (M3~) Next.js + Supabase + LLM 라우트
│       ├── vuln_logic/           # (M3) 정적 분석으로 못 찾는 취약점: IDOR·대량 할당·금액 변조·파일 간 SQL 흐름 (AI 보완 탐지 측정용)
│       ├── results/              # 샘플 결과 JSON (대시보드 트랙이 엔진 없이 화면 개발)
│       ├── secrets_zoo/          # 비밀값 노출 경로 모음 (.env, 키 파일, CI, Docker …)
│       └── expected/             # fixture별 기대 rule_id·위치 목록
│
└── bench/
    ├── ground_truth.yml          # 표본 id · WS · 기대(취약/안전) · 파일 · 줄
    ├── run.py                    # 탐지율·오탐 계산, WS·OWASP별 표
    └── report.md                 # 최근 벤치 결과
```

---

## 1. 설계 의도

### src 레이아웃
`src/wescope/` 구조를 쓴다. `import wescope`이 저장소 폴더가 아니라 **설치된 패키지**를 가리키게 되어, "내 PC에서는 되는데 설치하면 안 되는" 문제를 테스트 단계에서 잡을 수 있다.

### 규칙 데이터를 패키지 안에 둔다
v0.2는 규칙 YAML을 `data-files`(`share/wescope`)로 배포해 설치 위치를 따로 찾아야 했다. v1은 `src/wescope/rules/`에 두고 `importlib.resources`로 읽는다. 개발 모드와 설치 모드의 경로가 같아진다.

### analyzers/ = 영역별 한 파일(또는 한 패키지)
WS 영역과 파일이 1:1에 가깝게 대응한다. 규칙이 많은 WS-01(secrets)과 프레임워크별 파서가 필요한 WS-02(routes)만 하위 패키지로 나눈다.

### engine/ 과 analyzers/ 분리
탐지(무엇을 찾나)와 판정(어떻게 정리하나)을 분리한다. 판정 로직(정규화·비교·범위·점수)은 어떤 Analyzer가 추가되어도 바뀌지 않는다.

### taxonomy/ 분리
WS·OWASP 분류는 여러 곳(정규화, 범위 계산, 보고서, 대시보드 필터)에서 쓴다. 한 곳에서 로딩하고 캐시한다.

### models/ 분리
`Finding`, `ScanResult`를 별도 패키지에 두어 순환 참조를 막고, 엔진·서버·보고서가 같은 데이터 구조를 공유한다. JSON 변환(`to_json`/`from_json`)도 여기서만 한다. `schema_version`이 바뀌면 `from_json`에서 이전 형식을 변환한다.

### server/ 와 web/ 분리
`server/`는 API만, `web/`은 정적 파일만. 엔진은 서버를 모르고, 서버는 `scan.run_scan()`과 `store/`만 호출한다.

### fixtures/ 테스트 전략
- 취약 앱과 **같은 기능의 안전한 앱**을 함께 둔다. 탐지율과 오탐을 같은 기준으로 잰다.
- `conftest.py`가 fixture 폴더를 임시 폴더로 복사해 스캔하고, Git 시나리오(커밋됨·커밋 안 함·ignore됨)는 임시 Git 저장소로 만들어 확인한다.
- ChatGPT 테스트는 `fake_chatgpt.py`로 정해진 응답을 돌려줘 실제 구독 없이도 돈다. 실제 품질 측정(수정안 검증률 등)은 `bench/`에서 따로 한다.
- `expected/`의 기대 목록과 달라지면 테스트가 실패한다. 규칙을 바꿨다면 기대 목록도 같이 고친다.

---

## 2. 의존성 방향

```
__main__ / server / hook
        │
        ▼
      scan.py ─────────────┐
        │                  │
   ┌────┼──────────┬───────┼──────────┐
   ▼    ▼          ▼       ▼          ▼
collector  analyzers  engine  llm   report / store
   │          │          │      │        │
   └──────────┴────┬─────┴──────┴────────┘
                   ▼
           models · taxonomy · config · paths
```

- 아래쪽(models·taxonomy)은 위쪽을 import하지 않는다.
- analyzers는 engine·llm·server를 import하지 않는다.
- llm은 analyzers를 import하지 않는다 (Finding과 ScanContext만 받음).

---

## 3. 이름 규칙

| 대상 | 규칙 | 예 |
|---|---|---|
| rule_id | 영역 접두어 + 소문자 kebab | `secret-hardcoded`, `inject-sql`, `authz-idor`, `config-debug` |
| Semgrep 규칙 파일 | rule_id와 같은 이름 (여러 언어 규칙을 한 파일에) | `rules/semgrep/inject-sql.yml` |
| Analyzer id | 모듈 이름 | `secrets`, `routes`, `semgrep` |
| WS 코드 | `WS-01` ~ `WS-10` | |
| OWASP 코드 | `A05:2025`, `LLM01:2025`, `ASI01:2026` | |
| 체인 id | `chain-` 접두어 | `chain-authz-inject` |

---

## 4. 기존 코드(v0.2) → v1 대응

재작성할 때 **그대로 옮길 것 / 고쳐서 옮길 것 / 버릴 것**을 구분한다.

| v0.2 파일 | v1 위치 | 처리 |
|---|---|---|
| `scanner/ingest.py` | `collector/snapshot.py`, `files.py`, `ignore.py`, `sensitive.py` | 고쳐서 이식 — (HEAD export → 현재 파일 복사 + Git 상태로 변경)·제외·민감 파일 로직은 재사용, 트랙별로 분리 |
| `scanner/context.py` | `collector/inventory.py` | 고쳐서 이식 — 프로파일 결정론 부분만 |
| `scanner/static.py` | `scan.py`, `engine/runner.py` | 다시 작성 — 하드코딩된 탐지기 호출을 레지스트리로 |
| `scanner/detectors/secrets.py` | `analyzers/secrets/` | 고쳐서 이식 — 공급자 패턴·마스킹·자리표시 필터 재사용, `hidden` 부수효과를 `SecretRegistry`로 |
| `scanner/detectors/semgrep.py` | `analyzers/semgrep.py` | 고쳐서 이식 — 실패 시 예외 대신 `skipped`/`failed` |
| `scanner/detectors/routes.py` | `analyzers/routes/` | 고쳐서 이식 — 프레임워크별 파일로 분리, 함수 범위(scope) 추가 |
| `scanner/detectors/config.py` | `analyzers/config.py` | 이식 |
| `scanner/detectors/java.py` | `analyzers/java/` | M4에 이식 (v1 초기 범위 밖) |
| `scanner/normalize.py` | `engine/normalize.py` | 고쳐서 이식 — 지문 로직 재사용, OWASP 자동 분류 추가, JS 공백 정규화 |
| `scanner/models.py` | `models/` | 다시 작성 — KISA 필드 없음, WS·OWASP·설명 필드 |
| `scanner/history.py` | `store/history.py` | 다시 작성 — 새 스키마 |
| `scanner/kisa.py`, `rules/catalog/kisa-2026-web.yml` | — | **버림** |
| `rules/vibescan/*.yml` | `src/wescope/rules/semgrep/*.yml` | 고쳐서 이식 — rule_id 변경([RULES.md](RULES.md) §8), `metadata.kisa` 삭제, 한국어 설명 필드 추가 |
| `vibescan/cli.py` | `__main__.py`, `report/` | 다시 작성 — CLI 검사 명령 제거, 실행기(서버 시작·브라우저 열기)만 남김. 보고서 렌더링은 `report/`로 |
| `vibescan/dashboard.py` | `server/` | 고쳐서 이식 — 로컬 전용 미들웨어·티켓·clone 로직 재사용, API 파일 분리 |
| `vibescan/login.py`, `session.py`, `register.py` | `llm/auth.py` | 이식 |
| `vibescan/inference.py`, `analysis.py` | `llm/client.py`, `review.py`, `fixer.py`, `guards.py`, `prompts.py` | 고쳐서 이식 — 가드 추가, 5종 점검 계획(plan) 제거 |
| `vibescan/hook.py` | `hook.py` | 이식 |
| `vibescan/web/*` | `web/` | [DASHBOARD.md](DASHBOARD.md) 기준으로 다시 작성 (Pretendard·토큰 이름 체계·진행 표시 막대·diff 색은 재사용, 다크 테마·`theme.js`는 새로 작성, 설정은 드로어 대신 가운데 창 — DASHBOARD.md §1) |
| `vulnapp/` | `tests/fixtures/vuln_flask/` | 이식 + 같은 기능의 `clean_app/` 추가 |
| `bench/` | `bench/` | 고쳐서 이식 — `kisa` 키 → `category`(WS) |
| `tests/*` | `tests/` | 표본·기대값은 재사용, 테스트 코드는 새 구조에 맞게 |
| `docs/sprint*.md`, `technical.md`, `diagnosis-plan.md` | `docs/archive/` | 보관 (참고용) |

---

## 5. M1 엔진 구현에서 위 트리와 달라진 점 (2026-11-25)

필요 없는 파일을 만들지 않으려고 합친 것들이다. 책임과 의존성 방향은 그대로다 (`tests/test_layers.py`가 확인).

| 트리 | 실제 | 이유 |
|---|---|---|
| `collector/gitstate.py`, `ignore.py`, `files.py` | `collector/snapshot.py` 하나 | 걷기·제외·Git 상태가 한 번의 순회에서 끝난다 |
| `analyzers/secrets/files.py` … `_filters.py` (7개) | `secrets/__init__.py`(판정) + `secrets/patterns.py`(패턴·필터) | 규칙들이 같은 줄 순회를 공유한다 |
| `analyzers/routes/flask.py`, `fastapi.py` | `routes/python.py` | 두 프레임워크 모두 데코레이터 AST라 코드가 같다. Django는 URL과 view가 다른 파일이라 `routes/django.py`가 저장소 전체를 본다 |
| `rules/semgrep/config-cors.yml` | `rules/semgrep/config-js.yml` | JS 쪽 CORS·쿠키·약한 서명 키를 함께 담는다 |
| `tests/fixtures/expected/` | 표본 파일 안의 `# expect: 규칙` 주석 | 기대값이 코드 바로 위에 있어 어긋날 수 없다. 파일 단위 발견만 테스트에 적는다 |
| `tests/test_rules_semgrep.py`의 표본 | `tests/semgrep_samples/` + `# ruleid:` / `# ok:` 주석 | Semgrep 표준 주석 형식 |
| `tests/fixtures/results/` | 실제 스캔으로 만든 샘플 5개 (첫 검사·다시 검사(NEW/FIXED/오탐)·Git 비밀값·발견 없음·Semgrep 건너뜀) | `tests/test_contract.py`가 형식을 고정한다. 경로는 `/home/me/projects/…`로 바꿔 둔다 |
| `server/api_ignores.py`, `api_settings.py` | (B7·B8) | 오탐 표시·전역 설정은 쓰는 기능이 생길 때 추가 |
| `store/results.py`, `history.py` | + `store/lock.py` (`~/.wescope/scan.lock`, `launch.lock`) | 서버 작업 큐와 서버 없이 도는 hook이 같은 이력에 동시에 쓰지 않게, 동시에 실행한 `wescope`가 서버를 하나만 띄우게 |
| `scan.py`의 `run_scan()` | + `scan_repo(repo_id)` | `run_scan`은 저장 없이 검사만(테스트·수정안 검증), `scan_repo`는 직전 결과·오탐·꺼 둔 규칙을 store에서 읽고 결과를 저장 (작업 큐·hook이 호출) |
| `report/markdown.py` | 발견을 규칙별로 묶는다 | 같은 설명이 반복되지 않게 (대시보드 목록과 같은 묶음) |

- Semgrep 규칙의 같은 rule_id 변형(다른 언어·패턴)은 `inject-xss--js`처럼 `--` 뒤에 이름을 붙인다. 한국어 메타는 원본 하나에만 둔다.
- Semgrep은 임시 스냅샷에 We-Scope 전용 `.semgrepignore`를 써서 실행한다 (사용자 저장소 설정·Semgrep 기본값에 결과가 흔들리지 않게). Windows 한국어 로케일 때문에 `PYTHONUTF8=1`로 실행한다.
- 비밀값 표본은 `{{FAKE:종류}}` 표식으로 두고 테스트가 복사할 때 가짜 값으로 바꾼다 (실제 형식의 키를 커밋하지 않기 위해).

---

*Last updated: 2026-11-22*
