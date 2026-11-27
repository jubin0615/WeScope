# We-Scope 검증 보고서: OWASP Juice Shop · PyGoat

일부러 취약하게 만든 공개 앱 두 개에 We-Scope **정적 검사**(ChatGPT 분석 없이)를 돌리고, 직접 만든 정답지와 비교했다.

| 대상 | 커밋 (고정) | 스택 | 정답지 근거 |
|---|---|---|---|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | `c9f99228d9d56afb5f5ca7925376292f7fa44b13` (2026-11-19) | Express · TypeScript · Angular | `data/static/challenges.yml` 챌린지 118개 + 코드의 `vuln-code-snippet` 표시 + `solveIf` 위치 |
| [PyGoat](https://github.com/adeyosemanputra/pygoat) | `2aa4cc14f251e4a780e94e200aed6b36a5b15c21` (2026-11-01) | Django + Flask 실습 앱 24개 | `populate_labs.py`의 실습 목록 + 각 실습 코드의 취약 지점 |

두 앱의 코드는 이 저장소에 넣지 않았다. 앱 설치·실행·스크립트 실행은 하지 않았다 (정적 분석이라 필요 없음).

## 1. 한눈에 보기

| 지표 | Juice Shop | PyGoat |
|---|---|---|
| 검사한 파일 / 걸린 시간 | 1,491개 / 51.2초 | 459개 / 9.7초 (첫 실행 16.2초) |
| 정답지 항목 (취약점 단위) | 78개 (챌린지 118개 전부 포함) | 52개 (실습 24개 전부 포함) |
| ├ 정적 탐지 가능 | 42 | 33 |
| ├ 업무 로직 (규칙으로는 사실상 불가) | 28 | 16 |
| ├ 정적 불가 (런타임·OSINT·클라이언트) | 5 (챌린지 28개) | 0 |
| └ 지원 범위 밖 (의존성·Solidity·이미지) | 3 (챌린지 8개) | 3 |
| **탐지율** (정적 탐지 가능 항목 기준) | **12 / 42 = 29%** | **25 / 33 = 76%** |
| We-Scope 발견 | 113개 | 127개 |
| ├ 정답지와 일치 | 25 | 37 |
| ├ 정답지 밖이지만 실제 문제 | 9 | 76 |
| ├ 오탐 | **58** (그중 51개가 번역 파일) | 11 |
| └ 실행 안 되는 예제·테스트 코드 | 21 | 3 |
| **정밀도** (일치+실제) / (일치+실제+오탐) | **37%** (번역 파일 빼면 83%) | **91%** |

PRD 목표와 비교:

- **탐지율 90% 이상** — 둘 다 미달. PyGoat(Python)는 76%로 가깝고, Juice Shop(TypeScript·Angular)은 29%로 크게 모자란다.
- **안전 표본 오탐 0** — 이번 대상은 취약한 앱이라 이 지표는 잴 수 없다. 대신 Juice Shop에서 번역 파일 오탐 51개가 나왔다. 안전한 앱이어도 i18n 파일만 있으면 똑같이 나올 오탐이다.
- **파일 1,000개 60초 이내** — 통과. Juice Shop은 1,491개에 51초였다 (1,000개당 약 34초).

## 2. Juice Shop

**찾은 것 (12):** 로그인·검색 SQL 주입, `eval` 코드 주입(SSTI 챌린지), 프로필 이미지 SSRF, JWT RSA 개인키·Terraform 개인키 하드코딩, 시드 데이터의 평문 비밀번호·TOTP 비밀값, `premium.key` 커밋, ftp 백업 파일 두 개, 토큰 쿠키 SameSite 누락(CSRF).

**놓친 것 (30), 원인별:**

| 원인 | 항목 | 개수 |
|---|---|---|
| Angular `bypassSecurityTrustHtml`을 XSS sink로 보지 않음 | DOM·반사·저장형 XSS 6종 (JS-08~13) | 6 |
| 규칙이 아예 없음 | NoSQL `$where`·조건 주입 3, XXE 1, 디렉터리 목록(serve-index) 3, JSONP 1, 프록시 헤더 속도 제한 1 | 9 |
| 입력(source)을 못 알아봄 | `({ query }: Request)` 구조 분해(리다이렉트), zip 항목 이름(Zip Slip) | 2 |
| sink가 목록에 없음 | `vm.runInContext`(RCE 2종), `res.render(…, {...req.body})`(LFR), 문자열로 만든 pug 템플릿(CSP 우회 XSS) | 3 |
| 비밀값 판정이 놓침 | `createHmac` 인자 문자열, Hashids salt, `'IamUsedForTesting'`(값에 test가 있어 자리표시자로 버림), MD5 해시(앞뒤 3줄에 password가 없음) | 4 |
| 라우트 인식 한계 | finale-rest 자동 API, `/metrics`, 다른 파일에 있는 처리 함수(IDOR) | 3 |
| 그 밖에 | `jws.verify` 알고리즘 미고정, `errorhandler()` 미들웨어, vm 문자열 안의 `yaml.load` | 3 |

**정답지 밖 판정:** 실제 문제 9 (CORS 전체 허용, `cookieParser('kekse')`, 인증 없는 `/rest/admin/*` 2개, `error.message` 응답, `ctf.key` 커밋 등), 오탐 58, 예제·테스트 코드 21.

오탐 58개 중 **51개가 `frontend/src/assets/i18n/*.json`** 의 `"LABEL_PASSWORD": "Password"` 같은 화면 번역 문구였다. 키 이름에 PASSWORD가 들어 있다는 이유만으로 비밀값으로 봤다. 나머지 7개는 three.js·타입 정의의 TODO 3개, 존재하는 키만 통과하는 파일 읽기 3개, 인증 판단에 쓰지 않는 `jwt.decode` 1개다.

## 3. PyGoat

**찾은 것 (25):** SQL·명령·`eval`·pickle·`yaml.Loader`·경로 조작·SSRF, `|safe` XSS 2개, 약한 해시(MD5·SHA1·md5 재설정 토큰), 약한·하드코딩 비밀키와 계정, 디버그 모드, 템플릿 주석에 남은 관리자 비밀번호.

**놓친 것 (8):**

| 항목 | 원인 |
|---|---|
| PG-02 Pillow `ImageMath.eval(사용자 수식)` | sink 목록에 없음 |
| PG-20 `password == "P@$$w0rd"` | 비교문의 문자열은 비밀값으로 보지 않음 |
| PG-24 로그인 없이 비밀번호·권한 변경 | DB가 아니라 메모리 dict에 써서 쓰기 라우트로 판단하지 않음 |
| PG-33·41 `<script>` 안의 `{{ 변수 }}` | `\|safe`가 없으면 템플릿 XSS로 보지 않음 (JS 문맥은 자동 이스케이프로 안 막힘) |
| PG-38 입력을 템플릿 소스에 넣는 SSTI | 규칙 없음 |
| PG-42 XXE (`feature_external_ges` True) | 규칙 없음 |
| PG-48 `X-Frame-Options: ALLOWALL` | 보안 헤더 검사 없음 |

**정답지 밖 판정:** 실제 문제 76 (실습 앱마다 있는 디버그 모드·하드코딩 비밀키·쿠키 플래그·오류 노출·커밋된 DB 파일 등. 정답지는 실습의 학습 목표만 넣었기 때문에 많다), 오탐 11, 안내문 속 예시 3.
오탐 11은 로그인 폼이나 사용자 개념이 없는 실습 앱에 붙은 `authz-no-auth-write` 4개, 중괄호 하나짜리 설명문·`csrf_token|safe`·폼 위젯·고정 문구에 붙은 `|safe` 6개, 안내문의 SQL 주입 예시 1개다.

## 4. 고치기 쉬운 개선점 (효과 큰 순서)

| # | 개선 | 효과 (이번 정답지 기준) |
|---|---|---|
| 1 | 비밀값 검사에서 i18n·locale 번역 JSON을 빼거나, 값이 자연어 문장·키 이름과 같은 단어면 버림 | Juice Shop 오탐 51개 감소 → 정밀도 37% → 83% |
| 2 | Angular `DomSanitizer.bypassSecurityTrust{Html,Script,Url,ResourceUrl}(변수)` 패턴 규칙 (inject-xss) | Juice Shop +6 |
| 3 | 디렉터리 목록 노출 규칙: `serveIndex(`·`express.static(…, {dotfiles})`·Django `show_indexes=True` | Juice Shop +3 |
| 4 | XXE 규칙: Python `feature_external_ges, True`·`resolve_entities=True`, JS `noent: true`·`XML_PARSE_NOENT` | 둘 다 +1 |
| 5 | NoSQL 주입: `$where`에 문자열 결합·템플릿 리터럴, `find/update({ _id: req.body.x })` | Juice Shop +2~3 |
| 6 | JS source에 구조 분해 `({ body, query, params }: Request)` 추가, sink에 `vm.runInContext`·`new vm.Script` 추가 | Juice Shop +2 (리다이렉트·RCE) |
| 7 | 자리표시자 단어 `test`를 단어 경계로만 (`IamUsedForTesting` 같은 값은 통과) | Juice Shop +1 |
| 8 | Jinja `<script>` 블록 안 `{{ 변수 }}` 경고, `ImageMath.eval` sink | PyGoat +3 |

1~6만 해도 Juice Shop 탐지율은 약 29% → 62%, PyGoat는 76% → 79% (8까지 하면 88%) 정도로 오를 것으로 본다 (직접 다시 재 봐야 함).

## 5. 검증 중 발견한 We-Scope 자체 버그 (중요)

**PEM 개인키가 결과에 가려지지 않은 채 저장된다.** `lib/insecurity.ts:21`과 두 Terraform 파일의 `-----BEGIN RSA PRIVATE KEY-----…` 줄이 결과 JSON의 `evidence`에 **키 전체(약 900자)** 로 들어갔다. 다른 비밀값은 `admi••••`처럼 가려진다.
원인은 개인키 공급자 패턴이 머리글(`-----BEGIN … PRIVATE KEY-----`)만 맞추고, 가릴 값을 `SecretRegistry`에 등록하지 않는 것으로 보인다 (`analyzers/secrets/__init__.py` `_scan_text`). 그래서 대시보드에 키가 그대로 보이고, ChatGPT 분석을 켜면 그 줄이 가려지지 않은 채 전송될 수 있다 (전송 경로는 확인하지 않았다).
이 때문에 `bench/results/*.full.json`(전체 결과)은 gitignore했고, 저장소에는 rule_id·위치·심각도만 남긴 `*.json`을 둔다.

## 6. 한계

- 정답지와 분류(static/logic/runtime)는 사람이 코드를 보고 정했다. 특히 "업무 로직"과 "정적 탐지 가능"의 경계는 판단이 들어간다. 항목마다 근거 위치를 적어 두었으니 다르게 보면 YAML을 고치고 다시 돌리면 된다.
- 일치 판정은 같은 파일, ±3줄, 미리 정한 rule_id 중 하나. 원인은 같은데 위치가 다른 발견은 일치로 치지 않았다 (예: Juice Shop errorHandling 챌린지는 `server.ts:722`인데 We-Scope는 `lib/utils.ts:251`을 찾음 → 정답지 밖 실제 문제로 셈).
- PyGoat의 "정답지 밖 실제 문제"는 규칙 단위로 묶어 판정한 것이 많다 (`secret-*`·`config-*` → 실제). 하나하나 다시 보지는 않았다.
- 정답지 항목 JS-21(JWT 개인키)·JS-22(HMAC 키)는 챌린지가 아니라 코드 검토로 넣었다. 빼면 Juice Shop은 40개 중 11개 (28%)다.
- 한 번씩만 돌렸다. 시간은 캐시 상태에 따라 다르다 (PyGoat 16.2초 → 9.7초).
- ChatGPT 보완 탐지는 켜지 않았다. "업무 로직" 44개 항목이 그 대상이다.

## 다시 돌리기

```powershell
git clone https://github.com/juice-shop/juice-shop C:\path\juice-shop; git -C C:\path\juice-shop checkout c9f99228d9d56afb5f5ca7925376292f7fa44b13
python -I bench/run.py C:\path\juice-shop juice-shop
python -I -X utf8 bench/compare.py juice-shop C:\path\juice-shop
```

PyGoat도 같다 (이름 `pygoat`). `compare.py`는 정답지 자체도 확인한다: 없는 rule_id, Juice Shop 챌린지 118개·PyGoat 실습 24개 중 빠진 것, 판정이 안 된 발견이 있으면 멈춘다.
항목별 전체 표는 [results/juice-shop.compare.md](results/juice-shop.compare.md)와 [results/pygoat.compare.md](results/pygoat.compare.md)에 있다.
