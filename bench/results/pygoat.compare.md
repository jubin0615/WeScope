# pygoat 비교 결과

- 커밋 `2aa4cc14f251e4a780e94e200aed6b36a5b15c21` · 검사한 파일 459개 · 걸린 시간 9.7초
- 정적 탐지 가능 항목 33개 중 25개 찾음 (탐지율 76%); 챌린지·실습 근거 항목만 보면 33개 중 25개
- We-Scope 발견 127개 = 정답지 일치 37 + 정답지 밖 실제 문제 76 + 오탐 11 + 예제·테스트 코드 3 → 정밀도 91% (예제·테스트까지 오탐으로 치면 89%)

## 정답지 항목

| id | 취약점 | 위치 | CWE | OWASP 2025 | 구분 | 결과 | 근거·이유 |
|---|---|---|---|---|---|---|---|
| PG-01 | 업로드 YAML을 yaml.Loader로 load | `dockerized_labs/a9_uckv_lab/app.py:62` | CWE-502 | A08:2025 | 정적 탐지 가능 | 찾음 | inject-deserialize app.py:62 |
| PG-06 | 약한 비밀번호의 솔트 없는 SHA256 해시를 코드에 | `dockerized_labs/auth_failure_lab/app.py:46` | CWE-916 | A04:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded app.py:44, secret-hardcoded app.py:53, secret-hardcoded app.py:59, secret-hardcoded app.py:65, secret-hardcoded app.py:71 |
| PG-07 | 약한 SECRET_KEY | `dockerized_labs/auth_failure_lab/app.py:12` | CWE-321 | A04:2025 | 정적 탐지 가능 | 찾음 | config-weak-secret app.py:12 |
| PG-09 | 하드코딩한 secret_key | `dockerized_labs/broken_auth_lab/app.py:16` | CWE-321 | A04:2025 | 정적 탐지 가능 | 찾음 | config-weak-secret app.py:16 |
| PG-10 | 약한 평문 비밀번호 계정 | `dockerized_labs/broken_auth_lab/app.py:21` | CWE-521 | A07:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded app.py:21, secret-hardcoded app.py:26 |
| PG-12 | 재설정 토큰이 md5(email+시각) | `dockerized_labs/broken_auth_lab/app.py:103` | CWE-640 | A07:2025 | 정적 탐지 가능 | 찾음 | config-weak-hash app.py:103 |
| PG-14 | debug=True | `dockerized_labs/broken_auth_lab/app.py:147` | CWE-489 | A02:2025 | 정적 탐지 가능 | 찾음 | config-debug app.py:147 |
| PG-15 | 입력을 넣은 명령을 shell=True로 실행 | `dockerized_labs/command_injection_lab/app.py:29` | CWE-78 | A05:2025 | 정적 탐지 가능 | 찾음 | inject-command app.py:30 |
| PG-16 | 입력을 eval | `dockerized_labs/command_injection_lab/app.py:49` | CWE-95 | A05:2025 | 정적 탐지 가능 | 찾음 | inject-code app.py:49 |
| PG-17 | 비밀번호 MD5 | `dockerized_labs/crypto_failure_lab/app.py:38` | CWE-328 | A04:2025 | 정적 탐지 가능 | 찾음 | config-weak-hash app.py:38 |
| PG-18 | 비밀번호 SHA1 | `dockerized_labs/crypto_failure_lab/app.py:25` | CWE-328 | A04:2025 | 정적 탐지 가능 | 찾음 | config-weak-hash app.py:25 |
| PG-21 | 폼 입력을 pickle.loads | `dockerized_labs/insec_des_lab/main.py:40` | CWE-502 | A08:2025 | 정적 탐지 가능 | 찾음 | inject-deserialize main.py:40 |
| PG-25 | DEBUG=True로 오류 화면에 설정 노출 | `dockerized_labs/sde/app.py:7` | CWE-215 | A10:2025 | 정적 탐지 가능 | 찾음 | config-debug app.py:7 |
| PG-26 | app.config에 비밀값 하드코딩 (DB·API_KEY·PASS 등) | `dockerized_labs/sde/app.py:6` | CWE-798 | A07:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded app.py:9 |
| PG-28 | app.debug=True + 404 처리기의 비밀값이 디버그 화면에 | `dockerized_labs/sec_misconfig/app.py:8` | CWE-215 | A10:2025 | 정적 탐지 가능 | 찾음 | config-debug app.py:8 |
| PG-29 | JWT 서명 키 secret123 | `dockerized_labs/sec_misconfig/app.py:98` | CWE-321 | A04:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded app.py:98 |
| PG-31 | SENSITIVE_DATA·404 처리기에 비밀값 하드코딩 | `dockerized_labs/sec_misconfig/app.py:12` | CWE-798 | A07:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded app.py:12, secret-hardcoded app.py:13, secret-hardcoded app.py:56, secret-hardcoded app.py:57, secret-hardcoded app.py:58, secret-hardcoded app.py:59, secret-hardcoded app.py:60, secret-hardcoded app.py:63 |
| PG-32 | 쿠키 값을 pickle.loads | `dockerized_labs/software_integrity_lab/app.py:44` | CWE-502 | A08:2025 | 정적 탐지 가능 | 찾음 | inject-deserialize app.py:44 |
| PG-34 | f-string SQL | `dockerized_labs/sql_injection_lab/app.py:51` | CWE-89 | A05:2025 | 정적 탐지 가능 | 찾음 | inject-sql app.py:57 |
| PG-35 | 폼 값으로 파일 열기 (경로 조작) | `dockerized_labs/ssrf_lab/app.py:21` | CWE-22 | A01:2025 | 정적 탐지 가능 | 찾음 | inject-path app.py:22 |
| PG-36 | 폼 URL을 requests.get | `dockerized_labs/ssrf_lab/app.py:37` | CWE-918 | A01:2025 | 정적 탐지 가능 | 찾음 | inject-ssrf app.py:37 |
| PG-37 | /internal을 위조 가능한 X-Forwarded-For로만 막음 | `dockerized_labs/ssrf_lab/app.py:47` | CWE-348 | - | 정적 탐지 가능 | 찾음 | authz-admin-route app.py:53 |
| PG-39 | 검색어를 |safe로 출력 | `dockerized_labs/xss_lab/templates/lab1.html:30` | CWE-79 | A05:2025 | 정적 탐지 가능 | 찾음 | inject-xss-template lab1.html:30 |
| PG-40 | script 태그만 지우고 |safe로 출력 | `dockerized_labs/xss_lab/templates/lab2.html:24` | CWE-79 | A05:2025 | 정적 탐지 가능 | 찾음 | inject-xss-template lab2.html:24 |
| PG-52 | 템플릿 JS 주석에 관리자 비밀번호 | `dockerized_labs/sensitive_data_exposure/templates/profile.html:228` | CWE-798 | A07:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded profile.html:228 |
| PG-02 | 사용자 수식을 Pillow ImageMath.eval | `dockerized_labs/a9_uckv_lab/app.py:94` | CWE-95 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — PIL.ImageMath.eval을 코드 실행 sink로 보지 않음 |
| PG-20 | 비교문에 하드코딩한 비밀번호 P@$$w0rd | `dockerized_labs/crypto_failure_lab/app.py:88` | CWE-798 | A07:2025 | 정적 탐지 가능 | 놓침 | 비교문(==)의 문자열은 비밀값으로 보지 않음 (대입만 봄) |
| PG-24 | 로그인 없이 아무 계정 비밀번호·권한 변경 | `dockerized_labs/insufficient_logging_lab/app.py:54` | CWE-306 | A07:2025 | 정적 탐지 가능 | 놓침 | DB 쓰기가 아니라 메모리 dict를 고쳐 쓰기 라우트로 판단하지 않음 |
| PG-33 | username을 script 안 JS 문자열에 출력 | `dockerized_labs/software_integrity_lab/templates/lab2.html:43` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — <script> 안 {{ 변수 }}(JS 문맥 이스케이프) 패턴은 |safe가 없어 안 봄 |
| PG-38 | 제목·본문을 Jinja 템플릿 소스에 넣어 저장 후 렌더 (SSTI) | `dockerized_labs/template_injection_lab/app.py:25` | CWE-1336 | - | 정적 탐지 가능 | 놓침 | 규칙 없음 — 입력을 템플릿 소스에 넣는 SSTI (파일을 거쳐 render_template) |
| PG-41 | 입력을 script 태그 안에 출력 | `dockerized_labs/xss_lab/templates/lab3.html:28` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — <script> 안 {{ 변수 }}(JS 문맥 이스케이프) 패턴은 |safe가 없어 안 봄 |
| PG-42 | XML 파서 외부 엔티티 허용 | `dockerized_labs/xxe_lab/app.py:58` | CWE-611 | A02:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — XXE(feature_external_ges True) 규칙이 없음 |
| PG-48 | X-Frame-Options ALLOWALL (클릭재킹) | `challenge/labs/security_headers_lab/app.py:55` | CWE-1021 | A06:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — 보안 헤더(X-Frame-Options) 설정 검사 없음 |
| PG-03 | OTP 확인이 쿠키의 email을 믿음 | `dockerized_labs/auth_failure_lab/app.py:119` | CWE-565 | A08:2025 | 업무 로직 | 업무 로직 |  |
| PG-04 | 로그인 시도 횟수 제한 없음 | `dockerized_labs/auth_failure_lab/app.py:131` | CWE-307 | A07:2025 | 업무 로직 | 업무 로직 |  |
| PG-05 | 세션 정보를 서명 없는 쿠키에 | `dockerized_labs/auth_failure_lab/app.py:216` | CWE-565 | A08:2025 | 업무 로직 | 업무 로직 |  |
| PG-08 | admin=1 쿠키를 그대로 믿음 | `dockerized_labs/broken_access_lab/main.py:35` | CWE-565 | A08:2025 | 업무 로직 | 업무 로직 |  |
| PG-11 | 비밀번호 평문 저장·비교, 복잡도 검사 없음 | `dockerized_labs/broken_auth_lab/app.py:53` | CWE-256 | A06:2025 | 업무 로직 | 업무 로직 |  |
| PG-13 | 세션 토큰이 base64(이름:시각), 30일 유지 | `dockerized_labs/broken_auth_lab/app.py:57` | CWE-330 | A04:2025 | 업무 로직 | 업무 로직 |  |
| PG-19 | 로그인 쿠키가 서명 없는 base64 | `dockerized_labs/crypto_failure_lab/app.py:91` | CWE-565 | A08:2025 | 업무 로직 | 업무 로직 |  |
| PG-22 | 티켓 구매 수량·소유 확인 설계 결함 | `dockerized_labs/insecure_design_lab/app.py:104` | CWE-840 | - | 업무 로직 | 업무 로직 |  |
| PG-23 | 비밀번호·권한 변경을 기록하지 않음 | `dockerized_labs/insufficient_logging_lab/app.py:55` | CWE-778 | A09:2025 | 업무 로직 | 업무 로직 |  |
| PG-27 | X-Host 헤더 값으로 비밀 공개 | `dockerized_labs/sec_misconfig/app.py:30` | CWE-290 | A07:2025 | 업무 로직 | 업무 로직 |  |
| PG-30 | 토큰 발급 시 role을 요청에서 받음 | `dockerized_labs/sec_misconfig/app.py:95` | CWE-269 | A06:2025 | 업무 로직 | 업무 로직 |  |
| PG-46 | 프로젝트 API가 모든 속성 응답 (BOPLA) | `challenge/labs/bopla_lab/app.py:110` | CWE-213 | - | 업무 로직 | 업무 로직 |  |
| PG-47 | 쿠폰 중복 적용 | `challenge/labs/business_logic_lab/app.py:131` | CWE-840 | - | 업무 로직 | 업무 로직 |  |
| PG-49 | 송금 폼에 CSRF 방어 없음 | `challenge/labs/security_headers_lab/app.py:111` | CWE-352 | A01:2025 | 업무 로직 | 업무 로직 |  |
| PG-50 | 모든 사용자 카드·SSN을 인증 없이 응답 | `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:126` | CWE-862 | A01:2025 | 업무 로직 | 업무 로직 |  |
| PG-51 | API가 카드번호·SSN을 가리지 않고 응답 | `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:100` | CWE-359 | A01:2025 | 업무 로직 | 업무 로직 |  |
| PG-43 | 의존성 혼동·악성 패키지 흉내 | `dockerized_labs/dependency_attack_lab/app.py` | - | - | 지원 범위 밖 | 지원 범위 밖 |  |
| PG-44 | 패키지 주입 흉내 | `dockerized_labs/package_injection_lab/app.py` | - | - | 지원 범위 밖 | 지원 범위 밖 |  |
| PG-45 | 오픈소스 라이브러리 변조 흉내 | `dockerized_labs/open_source_library_attack_lab/app.py` | - | - | 지원 범위 밖 | 지원 범위 밖 |  |

## 정답지 밖 발견 판정

| 판정 | 규칙 | 개수 | 예 | 이유 |
|---|---|---|---|---|
| 실제 문제 | config-debug | 20 | `challenge/labs/bopla_lab/app.py:152` | 디버그·약한 비밀키·쿠키 플래그·오류 노출·ALLOWED_HOSTS 등 실제 위험한 설정 |
| 실제 문제 | secret-hardcoded | 15 | `challenge/labs/bopla_lab/app.py:48` | 실습 앱 코드·설정·DB 파일에 하드코딩·커밋된 비밀값 |
| 실제 문제 | config-weak-secret | 14 | `challenge/labs/business_logic_lab/app.py:5` | 디버그·약한 비밀키·쿠키 플래그·오류 노출·ALLOWED_HOSTS 등 실제 위험한 설정 |
| 실제 문제 | config-error-exposure | 8 | `challenge/views.py:374` | 디버그·약한 비밀키·쿠키 플래그·오류 노출·ALLOWED_HOSTS 등 실제 위험한 설정 |
| 실제 문제 | config-cookie-flags | 6 | `dockerized_labs/auth_failure_lab/app.py:208` | 디버그·약한 비밀키·쿠키 플래그·오류 노출·ALLOWED_HOSTS 등 실제 위험한 설정 |
| 실제 문제 | secret-data-file | 4 | `dockerized_labs/auth_failure_lab/instance/auth.db:0` | 실습 앱 코드·설정·DB 파일에 하드코딩·커밋된 비밀값 |
| 실제 문제 | config-default-credential | 3 | `challenge/labs/bopla_lab/app.py:50` | 디버그·약한 비밀키·쿠키 플래그·오류 노출·ALLOWED_HOSTS 등 실제 위험한 설정 |
| 실제 문제 | inject-open-redirect | 2 | `challenge/labs/security_headers_lab/app.py:189` | Referer로 되돌아가는 리다이렉트 (낮음) |
| 실제 문제 | git-hygiene | 1 | `.gitignore:0` | .gitignore에 비밀 파일 패턴이 없음 (권고) |
| 실제 문제 | config-allowed-hosts | 1 | `dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:13` | 디버그·약한 비밀키·쿠키 플래그·오류 노출·ALLOWED_HOSTS 등 실제 위험한 설정 |
| 실제 문제 | inject-xss-template | 1 | `dockerized_labs/ssrf_lab/templates/lab2.html:26` | SSRF로 가져온 응답을 |safe로 그대로 출력 |
| 실제 문제 | inject-xss-template | 1 | `dockerized_labs/xss_lab/templates/lab1.html:55` | 같은 실습 해설 블록의 {{query|safe}}도 실제로 렌더됨 |
| 오탐 | authz-no-auth-write | 4 | `dockerized_labs/a9_uckv_lab/app.py:73` | 로그인 폼 처리이거나 사용자 개념이 없는 단일 실습 앱 (DB 쓰기 권한과 무관) |
| 오탐 | inject-xss-template | 2 | `dockerized_labs/sensitive_data_exposure/templates/login.html:59` | Django 폼 필드 위젯 출력 (이미 안전 처리된 HTML) |
| 오탐 | secret-hardcoded | 1 | `dockerized_labs/sql_injection_lab/templates/index.html:57` | 안내문의 SQL 주입 예시 문자열 ('anything' OR '1'='1) |
| 오탐 | inject-xss-template | 1 | `challenge/templates/challenge.html:51` | csrf_token|safe — Django가 만든 토큰 값 |
| 오탐 | inject-xss-template | 1 | `dockerized_labs/insecure_design_lab/templates/lab.html:22` | error는 서버가 정한 고정 문구만 들어감 |
| 오탐 | inject-xss-template | 1 | `dockerized_labs/xss_lab/templates/index.html:114` | 설명문 속 {query|safe} (중괄호 하나) |
| 오탐 | inject-xss-template | 1 | `introduction/templates/Lab/XSS/xss.html:127` | 설명문 속 {query|safe} (중괄호 하나, Jinja가 해석하지 않음) |
| 예제·테스트 | secret-hardcoded | 3 | `dockerized_labs/insufficient_logging_lab/templates/lab1.html:58` | 실습 안내문·해설에 적힌 정답 계정·코드 예시 |
