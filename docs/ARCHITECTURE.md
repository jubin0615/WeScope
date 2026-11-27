# We-Scope — Architecture Design Document

> 요구사항은 [PRD.md](PRD.md), 규칙 상세는 [RULES.md](RULES.md), 단계별 코드 수준 설명은 [HOW_IT_WORKS.md](HOW_IT_WORKS.md)를 본다.

## 1. 실행 형태

We-Scope는 **대시보드 하나로 쓰는 로컬 도구**다. 사용자가 터미널에 입력하는 명령은 `wescope` 한 단어뿐이고, 그 명령은 로컬 서버를 띄우고 브라우저를 여는 일만 한다. 검사·결과·보고서·설정은 모두 대시보드에서 한다. CLI 검사 명령은 없다.

```
  [사용자]                          [사용자 PC 안]                               [외부]

  터미널에 wescope ──▶  로컬 서버 시작 (FastAPI, 127.0.0.1, 접속 티켓)
                        └─▶ 기본 브라우저로 대시보드 열기

  대시보드에서                 ┌──────────────────────────────┐
  [다시 스캔] 클릭 ─ API ────▶ │  로컬 서버                    │
                               │  ├─ 작업 큐 (한 번에 1개 스캔) │
  git commit                   │  └─ 스캔 엔진 호출            │ ── (ChatGPT 연결 시) ───────▶ OpenAI
  └─ post-commit hook ─ API ─▶ │                              │    위험 코드·관련 파일        Responses API
     (로컬 Git 폴더만,          └──────────────┬───────────────┘    (비밀값은 자리표시)      (내 ChatGPT 구독)
      서버가 꺼져 있으면 직접 검사)            │
                                    ~/.wescope/results · history.sqlite
                                               │
  대시보드 화면 ◀─────── 진행 상황·결과 (API) ──┘
```

### 1-1. 서버 수명

| 상황 | 동작 |
|---|---|
| `wescope` 입력 | 빈 포트에 서버 시작 → `~/.wescope/server.json`(포트·PID·접속 티켓, 권한 600) 기록 → `webbrowser`로 `http://127.0.0.1:<port>/?ticket=…` 열기 |
| 이미 실행 중인데 다시 입력 | `server.json`의 서버가 살아 있으면 새로 띄우지 않고 같은 주소를 브라우저로 다시 연다. 확인과 시작은 `~/.wescope/launch.lock` 안에서 하고, 잠금은 새 서버가 `/healthz`에 응답한 뒤 푼다 (동시에 실행해도 서버는 하나) |
| 터미널에서 `Ctrl+C` / 터미널 닫기 | 진행 중 스캔을 정리하고 종료, `server.json` 삭제 |
| 서버가 비정상 종료 | 다음 실행 때 `server.json`의 PID가 죽어 있으면 지우고 새로 시작 |
| 브라우저 탭만 닫음 | 서버는 계속 실행 (커밋 자동 검사를 계속 받기 위해) |

### 1-2. 커밋 자동 검사 (내부 진입점)

post-commit hook은 사용자가 쓰는 명령이 아니라 **설치된 패키지의 내부 모듈**을 호출한다.

```sh
# .git/hooks/post-commit  (로컬 Git 폴더를 연결하면 설치(기본 켬), 기존 hook은 그대로 두고 shebang 다음 줄에 넣음)
'<설치된 python 경로>' -P -m wescope.hook --repo <repo-id> --commit "$(git rev-parse HEAD)" >/dev/null 2>&1 & # wescope-hook <repo-id>
```

| 서버 상태 | 처리 |
|---|---|
| 실행 중 | `server.json`의 티켓으로 `POST /api/hook-trigger` → 서버 작업 큐에서 검사 (ChatGPT는 "자동 검사에서 ChatGPT 사용" 동의 시에만) → 열려 있는 대시보드는 목록만 조용히 갱신 (알림 없음) |
| 꺼져 있음 | `wescope.hook`이 ChatGPT 없이 직접 검사해 결과·이력 저장 → 다음에 `wescope`로 열면 최신 결과가 보임 |

자동 검사는 **로컬 Git 폴더 프로젝트에만** 있다. Git이 아닌 폴더와 GitHub 주소 프로젝트는 [다시 스캔]으로 검사한다.

- 위치는 `git rev-parse --git-path hooks/post-commit` (worktree를 따른다). `core.hooksPath`가 `.git` 밖(husky의 `.husky/` 등)을 가리키면 지원하지 않는다: 그 파일은 커밋될 수 있어 내 PC의 Python 경로가 팀 저장소로 퍼진다 (`Repo.hook == null`, 켜기 400).
- 끝에 덧붙이지 않는 이유: 기존 hook이 `exit`로 끝나면 실행되지 않는다. 셸 스크립트가 아닌 hook에는 넣지 않는다(켜기 400).
- 켜짐 여부는 **지금 Python 경로로 된 줄**이 있을 때만 `true`다. We-Scope를 다른 Python으로 다시 설치해 옛 경로 줄만 남으면(조용히 실패하는 줄) `false`로 보이고, 다시 켜면 새 경로로 바뀐다.
- python 경로는 작은따옴표 + `/`로 적어 Git for Windows의 sh에서도 그대로 돈다. `-P`는 hook이 도는 저장소 폴더를 import 경로에서 빼서, 저장소의 `wescope.py`·`json.py` 같은 파일이 설치된 코드 대신 실행되지 않게 한다. 끄기·연결 해제는 `wescope-hook <repo-id>` 줄만 지우고, 남은 것이 shebang뿐이면 파일을 지운다.
- 서버에는 `server.json`의 티켓을 `wescope_ticket` 쿠키로 보낸다 (대시보드와 같은 검사를 거친다).
- 서버가 없을 때의 디바운스: `~/.wescope/hook-<repo-id>.last`에 커밋을 적고 3초 기다린 뒤, 돌던 검사가 끝나길 기다렸다가 그 사이 더 새 커밋이 없을 때만 검사한다. 서버가 있으면 작업 큐가 저장소별 대기 작업을 하나로 합친다.

---

## 2. 데이터 흐름 (파이프라인)

```
대시보드 [다시 스캔] 클릭  또는  post-commit hook
│  POST /api/scans  /  POST /api/hook-trigger
│
▼
┌─────────────────────────────────────────────┐
│  0. Job (server/jobs.py)                    │
│  - 프로젝트·커밋 확인, 작업 큐에 등록       │
│  - 설정 병합 (프로젝트 설정 > 전역 설정 >   │
│    기본값) — 모두 대시보드 설정에서 관리     │
│  - 진행 단계를 대시보드로 전달 (SSE/폴링)   │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  1. Collector                               │
│                                             │
│  Snapshot: 폴더 → 현재 파일을 임시 폴더로    │
│            복사 (Git이면 파일별 추적 상태    │
│            기록) / GitHub → fetch 후 최신    │
│            커밋을 임시 폴더로 export          │
│                                             │
│  Track A: 텍스트 파일 (내용 지연 로딩)       │
│  Track B: 전체 파일 경로 (바이너리 포함)     │
│  Track C: .gitignore / .wescopeignore       │
│  Track D: 민감 파일 메타 (.env·키 파일 —     │
│           내용은 읽지 않음)                  │
│                                             │
│  Output: ScanContext                        │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  2. Inventory (정찰)                         │
│  - 언어 통계, 프레임워크 (Flask·FastAPI·     │
│    Express·Next.js·Spring)                  │
│  - 라우트 목록 (메서드·경로·핸들러·가드 단서)│
│  - 설정·매니페스트·BaaS 파일·LLM SDK·        │
│    에이전트 설정 파일                        │
│  - 영역별 적용성: WS-01~10 applies?         │
│                                             │
│  Output: AppProfile (ScanContext에 부착)    │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  3. Analyzer Engine (핵심)                  │
│                                             │
│  등록된 Analyzer를 고정 순서로 실행          │
│  - applies() 거짓 → not_applicable          │
│  - 도구 없음 → skipped (스캔은 계속)         │
│  - 예외 → failed (스캔은 계속)              │
│  - 탐지기별 타임아웃                         │
│                                             │
│  ① secrets   ② semgrep(주입·XSS 등)          │
│  ③ routes    ④ config / insecure-defaults   │
│  ⑤ baas      ⑥ dependencies                 │
│  ⑦ webhooks  ⑧ abuse-controls               │
│  ⑨ llm       ⑩ agent-config                 │
│                                             │
│  Output: RawHit[] + AnalyzerStatus[]        │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  4. Normalizer                              │
│  - 규칙 메타 결합: WS 영역, CWE, 심각도,     │
│    무엇·왜·어떻게(한국어), 수정 예시, 한계   │
│  - CWE → OWASP Top 10:2025 자동 부여         │
│  - 비밀값 마스킹 재확인                       │
│  - 지문 계산, 같은 위치 중복 병합             │
│                                             │
│  Output: Finding[]                          │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  5. ChatGPT 검토 (선택, AI.md §4·§5)        │
│  - 의심 발견 확인: Potential 발견을 주변     │
│    코드로 확인 → AI 확인 / 오탐 제안          │
│  - 보완 탐지: 인가·결제·대량 할당·파일 간    │
│    흐름 등 대상 파일 검토 → 새 발견          │
│  - 환각 방지: 인용 코드가 실제와 일치하는     │
│    것만 채택, AI 발견도 4번 정규화를 거침     │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  6. Correlator                              │
│  - 같은 핸들러·같은 키 값 범위에서 서로 다른 │
│    종류의 신호가 겹치면 체인 발견 추가       │
│    (원 발견은 유지)                          │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  7. Comparator                              │
│  - 직전 검사와 지문 대조                      │
│  - new / existing / fixed                   │
│  - 이번에 파싱 실패한 파일의 발견은 fixed로   │
│    처리하지 않고 "확인 불가"로 유지           │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  8. ChatGPT 수정안 (선택, AI.md §3)          │
│  - 대상: CRITICAL·HIGH 상위 그룹 (나머지는    │
│    대시보드에서 요청 시)                      │
│  - 맥락 수집 → 생성 → 임시 사본에 적용 →     │
│    문법 검사 → 탐지기 재실행 → 실패 시 1회    │
│    재요청 → 검증 상태 기록                    │
│  - 캐시: 코드가 같으면 이전 결과 재사용       │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  9. Aggregator                              │
│  - 검사 범위: WS 10개·OWASP 10개·ChatGPT     │
│    검토 범위 상태                             │
│  - 위험 점수, 심각도별 집계, NEW/FIXED 수     │
│  - 사용자가 끈 규칙·오탐 표시 반영            │
│                                             │
│  Output: ScanResult                         │
└─────────────┬───────────────────────────────┘
              ▼
┌─────────────────────────────────────────────┐
│  10. Store                                  │
│  - 결과 JSON·SQLite 이력 저장                │
│  - 보고서(Markdown·HTML)는 내려받기 요청 시   │
│    결과 JSON에서 생성                         │
└─────────────┬───────────────────────────────┘
              ▼
   대시보드에 "검사 완료" 이벤트 → 목록·요약 줄 조용히 갱신 (알림 없음)
```

---

## 3. 핵심 설계 원칙

### 3-1. 엔진과 화면 분리
엔진은 `ScanResult`(JSON)만 만든다. 대시보드와 보고서는 그 JSON을 읽기만 한다. 목록 묶기·정렬·탭 필터·수정 요청 프롬프트는 대시보드(클라이언트)가 결과 JSON만으로 만든다. 화면을 바꿔도 엔진은 건드리지 않는다. 엔진은 서버 없이도 `scan.run_scan()`으로 호출할 수 있어 테스트는 이 함수를 직접 쓴다.

### 3-2. 플러그인 구조 Analyzer
모든 탐지기는 같은 계약(`Analyzer`)을 따른다. 새 탐지기 = 파일 1개 + 레지스트리 1줄 + 테스트. 엔진·보고서·검사 범위 계산은 수정하지 않는다. 검사 범위는 각 Analyzer가 선언한 `categories`(WS 영역)와 `languages`로 자동 계산한다.

### 3-3. 실패 격리와 정직한 상태
탐지기 하나가 실패해도 스캔은 끝까지 간다. 실패한 영역은 "건너뜀(사유)"으로 표시하고, "미발견"과 섞지 않는다. 개발·테스트에서는 `strict` 모드로 실패를 그대로 드러낸다.

### 3-4. 설명은 규칙에 내장
Aguantar/vibescan의 `why/fix` 방식을 따른다. 모든 규칙은 한국어 **무엇(title)·왜(why)·어떻게(fix)·수정 예시·한계**를 메타데이터로 갖는다. 그래서 AI 없이도 완결된 보고서가 나온다. AI는 이 기본 설명을 내 코드 기준으로 구체화할 뿐이다.

### 3-5. 분류는 엔진이 결정
WS 영역은 규칙 메타데이터, OWASP는 CWE에서 계산한다. 규칙에 OWASP를 직접 쓰지 않으므로 둘이 어긋날 수 없다. AI는 분류를 바꿀 수 없다.

### 3-6. 공유 컨텍스트, 한 번만 수집
파일 목록·텍스트·AST·.gitignore·인벤토리는 `ScanContext`에서 한 번만 만들고 모든 Analyzer가 공유한다. 텍스트와 AST는 처음 요청될 때 읽고 캐시한다.

### 3-7. 정적 분석은 기준선, ChatGPT는 덧붙임
정적 분석 결과는 ChatGPT가 지우거나 분류를 바꿀 수 없다. ChatGPT는 확인 표시·새 발견·수정안을 **덧붙이고**, 출처(`source`)를 남긴다. ChatGPT를 끄면 정적 분석 결과만 남고, 켜면 그 위에 더해진다. 상세는 [AI.md](AI.md).

### 3-8. 결정성
같은 코드면 같은 결과가 나와야 한다. ChatGPT 결과도 코드 해시 기준 캐시로 같은 코드에는 같은 결과를 돌려준다. Analyzer 실행 순서 고정, 발견 정렬 키 고정(심각도 → 파일 → 줄 → 규칙), 지문에 시각·임시 경로를 넣지 않는다.

---

## 4. 데이터 모델

### ScanContext (엔진 내부 공유 객체)

| 필드 | 설명 |
|---|---|
| `root` | 스냅샷 임시 폴더 경로 (검사 대상 원본이 아님) |
| `source` | 종류(`folder` / `github`), 원래 경로 또는 URL, Git 여부, 커밋 SHA·브랜치(있으면) |
| `files` | 텍스트 파일 상대 경로 목록 (Track A) |
| `all_files` | 전체 파일 경로 (Track B) |
| `ignore` | `.gitignore`·`.wescopeignore` 매처 (Track C) |
| `sensitive_files` | 민감 파일 메타 — 경로·종류·Git 상태(커밋됨 / 커밋 안 함 / ignore됨 / Git 아님) (Track D) |
| `git_status` | 파일별 Git 상태 (Git 폴더일 때) |
| `profile` | `AppProfile` — 언어·프레임워크·라우트·매니페스트·적용성 |
| `secrets` | `SecretRegistry` — 이번 스캔에서 찾은 비밀값 (마스킹 기준, 읽기 전용 공유) |
| `skipped` | 인코딩·크기·권한 문제로 읽지 못한 파일과 사유 |
| `text(path)` / `python_ast(path)` | 지연 로딩 + 캐시 |

### RawHit (Analyzer 출력)

| 필드 | 설명 |
|---|---|
| `rule_id` | 규칙 ID (예: `inject-sql`) |
| `file`, `line`, `end_line` | 위치. `line = 0`은 파일 단위 발견(.env 커밋, .gitignore 없음 등) |
| `evidence` | 근거 코드 한 줄 (Normalizer가 마스킹) |
| `scope` | 함수명·라우트·함수 줄 범위 (상관 분석용) |
| `severity`, `confidence` | 비우면 규칙 기본값. Git 상태처럼 hit마다 달라질 때만 채운다 |
| `source` | `engine` / `ai` |
| `extra` | 규칙별 추가 정보 (예: 라우트, 탐지된 키 종류, 세부 CWE). `extra.kind`는 파일 단위 발견의 지문에 들어간다 |

### Finding (사용자에게 보이는 발견)

| 필드 | 설명 |
|---|---|
| `id` | `F-001` (스캔 안 순번) |
| `rule_id`, `category` | 규칙, WS 영역 (`WS-05`) |
| `cwe`, `owasp`, `owasp_ai` | `CWE-89`, `A05:2025`, `["LLM01:2025"]` |
| `severity`, `confidence` | `CRITICAL`~`INFO`, Likely/Potential |
| `source` | `engine`(정적 분석) / `ai`(ChatGPT 보완 탐지) |
| `confidence_source` | 신뢰도 근거: `flow`(흐름 확인) / `absence`(부재 추정) / `ai_confirmed`(ChatGPT 확인) / `ai`(ChatGPT 발견) |
| `title_ko` | 사람 말 제목 — 결과 중심 ("입력값으로 DB 내용을 마음대로 꺼내거나 지울 수 있어요") |
| `tech_name_ko` | 기술 이름 ("SQL 인젝션") — 판정 정보·보고서에서 사용 |
| `why_ko`, `fix_ko`, `avoid_ko`, `fix_example` | 무슨 일이 생길 수 있나·어떻게 고치나·하지 말 것·수정 예시 |
| `limitations_ko` | 이 발견이 증명하지 않는 것 |
| `location` | 파일·줄·라우트 |
| `evidence` | 마스킹된 근거 |
| `fingerprint` | `sha256(rule_id + file + 정규화 코드)` |
| `change` | new / existing / fixed / unknown |
| `introduced_in` | 처음 발견된 커밋 |
| `status` | open / dismissed(사용자 확정) |
| `triage` | ChatGPT 의심 확인 (B8-3a, AI.md §4). 확인하지 않은 발견은 `null`. `{"verdict": "confirmed"|"protected"|"unclear", "suggested": "dismiss"|null, "reason_ko", "impact_ko" (confirmed일 때만), "evidence": {"file", "line_start", "line_end"}|null (protected일 때만), "note_ko" (protected를 쓰지 않은 이유)|null, "instruction_suspect": bool, "cache_key"}`. 대상은 HIGH 이상 `confidence_source == "absence"`. confirmed면 `confidence` Likely·`confidence_source` `ai_confirmed`. protected는 근거 줄을 실제 코드와 대조해 맞을 때만이고 **오탐 제안**일 뿐 `status`는 바꾸지 않는다 (오탐 처리는 사용자가 ignores API로). 규칙·분류·심각도는 바꾸지 않는다 |
| `fix` | 수정안 (그룹 단위, 같은 `rule_id`의 대표(첫) 발견에 붙음): `summary_ko`, `diff`(비밀값은 `«WS_SECRET_n»` 자리표시 그대로), `files`, `behavior_change_ko`, `follow_ups`, `new_dependencies`, `test_hint_ko`, `confidence`, `verification`(`verified` / `partial` / `failed`), `checks`(`apply`·`syntax`·`rescan`: true/false/null, `reasons`: 실패 이유 문장), `attempts`(1~2), `cache_key`, `instruction_suspect`(보낸 코드에 지시문 같은 텍스트가 있었음). 샘플: `tests/fixtures/results/with-fix.json` |
| `chain`, `related` | 체인 발견일 때 구성 발견 |

### ScanResult (JSON 최상위)

| 필드 | 설명 |
|---|---|
| `schema_version` | `1` |
| `scan_id`, `scanned_at`, `trigger` | 식별·시각·`manual`([다시 스캔]) / `hook`(커밋 자동 검사) |
| `source` | `folder` / `github`, 경로 또는 URL, Git 여부 |
| `repo`, `commit`, `baseline_scan` | 대상, 커밋(있으면), 비교 기준이 된 직전 검사 |
| `profile` | 앱 프로파일 요약 |
| `analyzers` | Analyzer별 status·소요 시간·사유 |
| `coverage` | WS 10개 상태. JSON에는 코드값(`vulnerable`·`clean`·`partial`·`not_applicable`·`skipped`·`manual`)만 두고 한국어는 보고서·화면이 붙인다 |
| `owasp_coverage` | OWASP A01~A10 상태 |
| `ai_coverage` | ChatGPT 검토 범위(업무 로직 인가·결제·파일 간 흐름·미지원 언어) 상태 |
| `findings` | Finding[] |
| `summary` | 심각도별 개수, new/fixed 개수, 위험 점수 |
| `ai` | ChatGPT를 쓰지 않은 검사는 `null`. B8-1: `{"level", "model" (요청 전에 멈췄으면 null), "requests", "cache_hits", "triage": {"confirmed", "protected", "unclear", "remaining"} (B8-3a), "fixes": {"verified", "partial", "failed"}, "budget_exceeded" (확인·수정안 중 하나라도 예산 초과), "remaining_groups", "error": {"kind": "login"\|"plan"\|"limit"\|"error", "message"} \| null}`. AI 발견·폐기 수는 B8-3에서 추가 |

---

## 5. 구성 요소 책임

| 구성 요소 | 책임 | 하지 않는 것 |
|---|---|---|
| Collector | 스냅샷, 파일 수집, 제외, 민감 파일 메타 | 탐지 판단 |
| Inventory | 프레임워크·라우트·설정·매니페스트 파악, 적용성 판정 | 발견 생성 |
| Analyzer | 한 영역의 RawHit 생성, 상태 보고 | 심각도 재조정, 다른 Analyzer 호출 |
| Normalizer | 규칙 메타 결합, OWASP 부여, 지문, 중복 병합 | 탐지 |
| Correlator | 체인 발견 추가 | 원 발견 삭제 |
| Comparator | 변화 상태 계산 | 결과 저장 |
| ChatGPT 검토 | 의심 발견 확인, 보완 탐지(검증 통과분만), 설명 구체화 | 정적 발견 삭제·분류 변경, HIGH 이상 자동 오탐 처리 |
| ChatGPT 수정안 | 맥락 수집, 수정안 생성, 로컬 검증(적용·문법·재검사), 재요청 | 사용자 코드에 적용 |
| Aggregator | 범위·점수·요약, 사용자 표시 반영 | 발견 수정 |
| Reporter | 결과 JSON → Markdown·HTML 보고서 | 판단 |
| Store | 결과 파일·SQLite 이력 저장 | 판단 |
| Server | 대시보드 정적 파일·API, 작업 큐, 서버 수명(`server.json`), 로그인 흐름 | 엔진 로직 |
| Dashboard (web) | 위험 목록 묶기·정렬·탭, 상세·diff 표시, 프롬프트 조립 | 탐지·분류 |
| Hook | 커밋 감지 → 서버에 검사 요청, 서버가 없으면 직접 검사 | 사용자 명령 제공, 사용자 알림 |

---

## 6. 로컬 저장 위치

```
~/.wescope/
├── config.toml          # 전역 설정 (AI 사용, 자동 검사 AI 동의, 테마) — 대시보드 설정에서 편집
├── server.json          # 실행 중인 서버의 포트·PID·접속 티켓 (권한 600, 종료 시 삭제)
├── auth.json            # ChatGPT 등록(client_id)·토큰. Windows는 DPAPI로 암호화(현재 사용자만 풂), 그 밖은 권한 600
├── *.lock               # 프로세스 간 잠금: scan(검사 저장)·launch(서버 시작)·auth(토큰 갱신)
├── history.sqlite       # 프로젝트·프로젝트별 설정·스캔·발견·오탐 표시 이력
├── repos/               # GitHub 주소로 clone한 저장소 (We-Scope 전용, 검사 때 최신으로 맞춤)
├── ai-cache/            # ChatGPT 결과 캐시 (코드 해시 기준, 비밀값 없음)
└── results/
    └── <repo-id>/<scan-id>.json
```

- 코드 원문은 저장하지 않는다. 근거 코드 몇 줄(마스킹됨)만 Finding에 남긴다.
- 프로젝트 연결을 해제하면 해당 결과·이력을 지울 수 있다.

---

## 7. 로컬 서버 API (FastAPI, `127.0.0.1`)

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/` | 대시보드 (접속 티켓 필요, 확인 후 쿠키로 교체) |
| GET | `/api/state` | 첫 화면 판단용: 프로젝트 유무, 마지막 프로젝트, 진행 중 스캔 |
| GET | `/api/repos` | 연결된 프로젝트 목록 (프로젝트 선택 메뉴: 종류·최고 심각도·자동 검사 여부) |
| POST | `/api/repos` | 프로젝트 추가: `{"path": "…"}` 또는 `{"github": "…"}` (GitHub면 clone) → 바로 첫 검사 |
| DELETE | `/api/repos/{id}` | 연결 해제 (+ 이력 삭제 선택) |
| POST | `/api/repos/{id}/hook` | post-commit hook 설치·해제 (로컬 Git 폴더만) |
| POST | `/api/scans` | [다시 스캔] → `scan_id` (폴더는 현재 파일, GitHub는 fetch 후 최신 커밋) |
| GET | `/api/scans/{id}` | ScanResult |
| GET | `/api/repos/{id}/history` | 검사별 점수·변화 |
| GET | `/api/scans/{id}/events` | 진행 단계·로그·완료 이벤트 (SSE) |
| POST | `/api/scans/{id}/groups/{rule_id}/fix` | 수정안 만들기·다른 수정안 (요청 시 생성, 진행은 SSE) |
| POST / DELETE | `/api/repos/{id}/ignores` | 오탐 표시·되돌리기 (지문 단위, 이유 포함) |
| GET | `/api/scans/{id}/export?format=md\|html\|json` | 보고서·결과 JSON 내려받기 |
| GET/POST | `/api/settings` | 전역 설정 |
| GET/POST | `/api/repos/{id}/settings` | 프로젝트 설정 (제외 패턴, 꺼 둔 규칙) |
| POST | `/api/auth/login` · `/api/auth/logout` · GET `/api/auth` | ChatGPT 로그인 |
| POST | `/api/hook-trigger` | hook이 호출 (로컬 전용) |

모든 요청은 Host·Origin을 `127.0.0.1`로 제한하고, 실행마다 발급하는 티켓을 확인한다.

### 7-1. 구현된 API 형식 (B6 동결)

> 이 표와 `tests/fixtures/results/*.json`이 대시보드와 서버 사이의 계약이다. 바꾸려면 이 표 → 서버 → 샘플·테스트 순으로 바꾼다.
> 오류 응답은 모두 `{"detail": "한국어 메시지"}`. B7·B8에서 추가한 행은 `(B7)`·`(B8)`로 표시했다.

| 요청 | 성공 응답 | 실패 |
|---|---|---|
| `GET /?ticket=…` | `303 → /` + `wescope_ticket` 쿠키 (HttpOnly, SameSite=Strict) | 401 |
| `GET /healthz` (티켓 불필요) | `{"app": "wescope", "pid": 1234}` | — |
| `GET /auth/callback` (B8, 티켓 불필요) | OpenAI 승인 뒤 브라우저가 돌아오는 곳. 처음 연결이면 등록 결과(`client_id`)를 저장하고 `303 →` 로그인 승인 주소, 로그인이면 code를 토큰으로 바꿔 저장하고 "연결했어요" 페이지. SameSite=Strict 쿠키가 실리지 않는 요청이라 티켓 대신 이번 시도의 `state`(1회용, 5분)·PKCE·nonce로 확인 | 400 페이지 (state 불일치·만료, 승인 거절, 계정 확인 실패) |
| `GET /api/state` | `{"repos": 2, "last_repo": "<repo_id>" \| null, "running": Job \| null, "latest_scan": "<scan_id>" \| null}` — `latest_scan`(B7)은 모든 저장소 중 마지막 검사. 화면은 5초마다 확인해 처음 보는 `running`은 SSE로 지켜보고, `latest_scan`이 바뀌면 목록·결과를 다시 읽는다 (커밋 자동 검사를 알림 없이 반영) | — |
| `GET /api/catalog` (F3 추가) | `{"ws": [{"code": "WS-01", "name_ko": "비밀값 노출"}, …], "owasp": [{"code": "A01:2025", "name": "Broken Access Control"}, …]}` — 화면이 코드값에 붙이는 이름 | — |
| `GET /api/repos` | `[Repo, …]` | — |
| `POST /api/repos` `{"path": "…"}` 또는 `{"github": "https://github.com/o/r", "branch"?: "…"}` (+ `"name"?`) | `201 {"repo": Repo, "scan_id": "…"}` — 바로 첫 검사를 큐에 넣음 | 400 (둘 다/둘 다 없음, 없는 폴더, GitHub 형식 아님) |
| `DELETE /api/repos/{id}` | `204` — 이력·결과 JSON·전용 clone 삭제 | 404, 409 (검사 중) |
| `GET /api/repos/{id}/settings` | `{"disabled_rules": [rule_id], "excludes": ["pattern"]}` | 404 |
| `POST /api/repos/{id}/settings` (둘 중 보낸 것만 바뀜) | 위와 같은 형식 | 400 (모르는 규칙, 패턴 200자 초과·200개 초과), 404 |
| `POST /api/scans` `{"repo_id": "…"}` | `202 {"scan_id": "…"}` — 같은 저장소가 이미 대기 중이면 그 scan_id | 404 |
| `GET /api/scans/{scan_id}` | ScanResult JSON (§4) | 404, 409 (아직 검사 중) |
| `GET /api/scans/{scan_id}/events` | SSE. `event: progress` (data: Job) 0회 이상 → `event: done` 또는 `event: failed` 1회로 끝남 | 404 |
| `GET /api/scans/{scan_id}/export?format=md\|json` | 첨부 파일 `wescope-<폴더명>-<scan_id>.<format>` | 400 (다른 format), 404 |
| `POST /api/repos/{id}/hook` `{"enabled": bool}` (B7) | `{"hook": bool}` | 400 (GitHub·Git 아닌 폴더, hook이 `.git` 밖(husky 등), 셸이 아닌 기존 hook), 404 |
| `POST /api/hook-trigger` `{"repo_id"}` (B7, hook 전용) | `202 {"scan_id"}` — trigger `hook`. 같은 저장소가 대기 중이면 그 scan_id | 404 |
| `GET /api/repos/{id}/history?limit=50` (B7, 최대 500) | `[ScanSummary, …]` 최근 검사부터 | 404 |
| `GET /api/repos/{id}/ignores` (B7) | `[{"fingerprint", "reason", "created_at"}, …]` 표시한 순서 | 404 |
| `POST /api/repos/{id}/ignores` `{"fingerprint", "reason"?}` (B7) | `201` + 위 목록. **다음 검사부터** 그 발견이 `dismissed` (지금 결과 JSON은 바뀌지 않음) | 400 (지문 형식, 이유 500자 초과), 404 (최근 결과에 없는 지문) |
| `DELETE /api/repos/{id}/ignores/{fingerprint}` (B7) | `204` — 다음 검사부터 다시 `open` | 404 |
| `GET /api/settings` (B7, B8에서 `ai_*` 추가) | `{"theme": "system"\|"light"\|"dark", "ai_level": "deep"\|"basic"\|"off", "ai_on_hook": bool}` — `~/.wescope/config.toml`. 기본 `system`·`deep`·`false`. `ai_on_hook`이 false면 커밋 자동 검사에서는 ChatGPT를 쓰지 않는다 (AI.md §2) | — |
| `POST /api/settings` (B7, 보낸 항목만 바뀜) | 위와 같은 형식 | 400 (허용 값 아님) |
| `GET /api/auth` (B8) | `{"state": "login"\|"plan"\|"ready", "message"}` — 저장된 토큰만 보고 네트워크는 쓰지 않는다. `plan`은 구독 사용 승인이 없음. 마지막 연결 시도가 실패했으면 그 이유가 `message` | — |
| `POST /api/auth/login` (B8) | `{"url": "https://auth.openai.com/…"}` — 화면이 새 탭으로 연다. 다시 부르면 앞 시도는 무효 | — |
| `POST /api/auth/logout` (B8) | `204` — 이 PC의 토큰만 지운다 (등록·ChatGPT 쪽 앱 연결은 그대로) | — |
| `POST /api/scans/{scan_id}/groups/{rule_id}/fix` `{"retry"?: bool}` (B8) | `202 {"scan_id"}` — [수정안 만들기]·`retry`면 [다른 수정안](지금 diff를 채택하지 않음으로 넘김). 작업 큐에서 지금 파일 기준으로 만들고 그 검사의 결과 JSON 대표 발견 `fix`에 붙여 다시 저장한다. 진행은 같은 `/api/scans/{scan_id}/events` (Job `rule_id`가 채워짐) | 404 (검사 없음, 그 규칙의 열린 발견 없음), 409 (가장 최근 검사가 아님, ChatGPT 연결 전) |

- **Repo**: `{"id", "kind": "folder"|"github", "location", "branch", "name", "disabled_rules", "excludes", "created_at", "hook": bool | null, "last_scan": ScanSummary | null}` — `hook`(B7)은 hook 파일에서 바로 읽은 자동 검사 켜짐 여부, 로컬 Git 폴더가 아니거나 hook이 `.git` 밖이면 `null`. 로컬 Git 폴더는 연결할 때 켠다 (PRD P6 기본 켬)
- **ScanSummary**: `{"id", "scanned_at", "trigger", "commit_sha", "baseline", "risk_score", "summary"}`
- **Job**: `{"scan_id", "repo_id", "trigger": "manual"|"hook", "status": "queued"|"running"|"done"|"failed", "stage": "collect"|"analyze"|"organize"|"ai"|"save"|null, "error", "summary", "rule_id", "ai_progress"}` — B8: `stage == "ai"`는 ChatGPT 수정안 단계(연결했을 때만), `ai_progress`는 그때 `{"task": "triage"|"fix", "done", "total"}`(확인 n/m → 수정안 n/m), 아니면 null. `rule_id`는 수정안 작업이면 그 규칙, 검사면 null
- SSE는 0.2초마다 **현재 상태**를 보낸다. 빠른 스캔에서는 중간 단계가 생략될 수 있으니 화면은 마지막으로 받은 `stage`만 보여 준다.
- 작업 큐는 한 번에 1개만 돈다. 서버를 끄면(Ctrl+C) 돌던 스캔은 끝까지 마치고 대기 작업은 버린다.

---

## 8. Collector 안전장치

| 보호 | 구현 |
|---|---|
| 읽기 전용 | 폴더는 현재 파일을 임시 폴더로 복사해 검사, GitHub는 We-Scope 전용 clone에서 최신 커밋을 임시 폴더로 export. 원본 폴더에 쓰지 않음 |
| Git 상태 | `git ls-files`·`git check-ignore`로 파일별 커밋됨 / 커밋 안 함 / ignore됨 기록 (Git 폴더일 때) |
| 심볼릭 링크 | 건너뜀 (범위 밖 접근·무한 루프 방지) |
| 인코딩 | UTF-8 실패 시 건너뜀 + `skipped` 기록 |
| 대용량 | 5MB 초과 건너뜀 |
| 바이너리 | 존재만 기록, 내용 읽지 않음 |
| 민감 파일 | `.env`·키·인증 파일은 내용 미열람, 경로·종류만 |
| 임시 폴더 | 스캔 종료 시 삭제 (실패해도 `finally`) |

---

## 9. 상태와 오류 처리 정책

| 상황 | 처리 |
|---|---|
| Semgrep 미설치·실행 실패 | `semgrep` Analyzer `skipped`/`failed`, WS-05 "건너뜀(사유)", 나머지 진행. Semgrep은 기본 의존성이라 보통 함께 설치되고, We-Scope를 실행한 Python의 스크립트 폴더 → PATH 순으로 찾는다 |
| Python 파일 파싱 실패 | 해당 파일만 `partial`, 그 파일의 이전 발견은 fixed가 아닌 `unknown` |
| ChatGPT 로그인 안 함 / 사용량 초과(429) / 자격 없음(403) | ChatGPT 단계 생략 또는 즉시 중단, `ai.status`에 사유, 정적 결과와 그때까지의 ChatGPT 결과는 유지 |
| ChatGPT 응답 형식 오류 | 해당 요청만 제외, 재시도 1회 |
| AI 발견 인용 코드 불일치 | 폐기, `ai.discarded`에 집계 |
| 수정안 적용·문법·재검사 실패 | 실패 이유를 붙여 1회 재요청 → 그래도 실패면 `verification: failed` + 규칙 기본 예시 |
| 스캔당 ChatGPT 예산 초과 | 남은 작업 건너뜀, ChatGPT 검토 범위에 "일부" 표시 |
| GitHub fetch 실패 | 이전 결과 유지, 상태 문장에 사유 |
| 서버 꺼진 상태의 hook | ChatGPT 없이 검사·저장, 다음에 `wescope`로 열 때 최신 결과로 표시 |
| 포트 충돌 | 다른 빈 포트로 시작 (주소는 `server.json`에 기록) |
| 브라우저 자동 열기 실패 | 터미널에 접속 주소를 표시 |
| 연속 커밋 | 디바운스, 마지막 커밋만 검사 |

---

## 10. 확장 지점

| 확장 | 방법 |
|---|---|
| 새 탐지기 | `analyzers/`에 Analyzer 추가 + 레지스트리 등록 + `rules/catalog`에 규칙 메타 |
| 새 AI 보완 탐지 대상 | `llm/review_targets.py`에 대상 선정 규칙 + 검토 관점 + 허용 `vuln_type`(CWE 지정) 추가 |
| 새 Semgrep 규칙 | `rules/semgrep/*.yml` 추가 (메타: rule_id·category·cwe·한국어 설명) + 취약/안전 표본 |
| 새 언어 | Analyzer의 `languages`에 추가, 검사 범위가 자동 반영 |
| 새 보고서 형식 | `report/`에 Reporter 추가 (ScanResult만 입력) + 내려받기 메뉴 항목 |
| 새 화면 요소 | `web/`만 수정 (결과 JSON 필드가 충분하면 서버·엔진 수정 없음) |
| 동적 점검 | `Analyzer`와 같은 계약의 `Probe` (M4 이후) |

---

*Last updated: 2026-11-22*
