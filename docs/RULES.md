# We-Scope — 탐지 규칙 카탈로그

> 이 문서는 **무엇을, 어떤 근거로, 어떤 분류로** 찾는지의 기준이다. 코드의 규칙 메타데이터(`rules/catalog/*.yml`, `rules/semgrep/*.yml`)는 이 문서와 일치해야 한다.

표기
- **단계**: M1(엔진 MVP) · M2 · M3 · M4 — [PRD.md](PRD.md) §11
- **신뢰도**: L = Likely(흐름 직접 확인) · P = Potential(부재 추정)
- **OWASP**: CWE에서 자동 계산되는 OWASP Top 10:2025 코드. "—"는 Top 10에 매핑되지 않음. 괄호는 LLM(2025)·Agentic(2026) 목록
- 모든 규칙은 한국어 `title_ko`(사람 말 제목) · `tech_name_ko`(기술 이름) · `why_ko`(무슨 일이 생길 수 있나) · `fix_ko`(어떻게 고치나) · `avoid_ko`(하지 말 것) · `fix_example` · `limitations_ko`를 가진다. 대시보드 카드 제목은 `title_ko`, 판정 정보와 보고서 소제목은 `tech_name_ko`를 쓴다

---

## 1. We-Scope Top 10 한눈에 보기

| | 영역 | 바이브코딩에서 흔한 모습 | OWASP 2025 | 단계 |
|---|---|---|---|---|
| **WS-01** | 비밀값 노출 | 소스에 API 키, `.env` 커밋, `NEXT_PUBLIC_`에 서버 키 | A07, A01 | M1 |
| **WS-02** | 인증·인가 누락 | 관리자 API에 로그인만 확인, 남의 `id`로 조회 | A01, A04, A07 | M1 (Next.js M4) |
| **WS-03** | 데이터 계층 공개 | Supabase RLS 미설정, Firebase `if true` | A01, A08 | M3 |
| **WS-04** | 위험한 의존성 | `git+` 의존성, `latest`, 잠금 파일 없음 | A03, A08 | M4 |
| **WS-05** | 입력값 주입 | f-string SQL, `innerHTML`, `eval(req.body)` | A05, A01, A06, A08 | M1 |
| **WS-06** | 위험한 기본값 | `debug=True`, CORS `*`, `verify=False`, 약한 서명키 | A02, A04, A07, A10 | M1 |
| **WS-07** | 웹훅·결제 검증 누락 | 서명 검증 없는 결제 웹훅, 요청의 `amount` 신뢰 | A08, A06 | M3 |
| **WS-08** | 남용 방지 부재 | 로그인·LLM 라우트에 rate limit 없음 | A07 (LLM10) | M3 |
| **WS-09** | LLM 연동 취약 | 입력을 프롬프트에 결합, 모델 출력을 `eval` | A05 (LLM01·02·05) | M3 |
| **WS-10** | AI 에이전트 설정 오염 | allow-all 권한, 미고정 MCP, 지시 주입 | A08 (ASI01~05) | M4 |

---

## 2. 규칙 상세

### WS-01 비밀값 노출 — `analyzers/secrets/`

| rule_id                  | 찾는 것                                                                                                                                                                                                                                                                                                                                           | 심각도                                  | 신뢰도 | CWE     | OWASP | 단계  |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | --- | ------- | ----- | --- |
| `secret-env-file`        | `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.staging`, `.env.test`가 **커밋됨** (CRITICAL) / 커밋 안 됐고 `.gitignore`에도 없어 **다음 커밋에 들어갈 수 있음** (HIGH) / Git이 아닌 폴더에 있음 (MEDIUM·P, "공유·배포 때 포함되지 않게 확인"). `.gitignore`로 제외된 로컬 `.env`는 발견 아님. 내용은 읽지 않음                                                                           | CRITICAL / HIGH / MEDIUM             | L   | CWE-540 | A01   | M1  |
| `secret-credential-file` | `serviceAccountKey.json`, `*-service-account.json`, `credentials.json`, `client_secret*.json`, `application_default_credentials.json`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `terraform.tfstate`, `terraform.tfvars`, `.kube/config`, `.pgpass` 커밋됨                                               | CRITICAL                             | L   | CWE-540 | A01   | M1  |
| `secret-hardcoded`       | 공급자 키 형식(`sk-`, `sk-ant-`, `sk_live_`, `rk_live_`, `AKIA`, `ghp_`, `glpat-`, `xoxb-`/`xoxp-`, JWT, `-----BEGIN … PRIVATE KEY-----`), 연결 문자열(`postgres://user:pass@`, `mongodb://`, `mysql://`, `redis://:pass@`, `amqp://`), Slack·Discord 웹훅 URL, 인증정보 이름 변수(`password`, `secret`, `token`, `api_key`, `client_secret`, `private_key`)의 리터럴 값 | HIGH (AWS·service_role·개인키 CRITICAL) | L   | CWE-798 | A07   | M1  |
| `secret-frontend-env`    | `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_PUBLIC_`, `EXPO_PUBLIC_` 접두어 + `SECRET`·`PASSWORD`·`PRIVATE`·`SERVICE_ROLE`·`TOKEN` 이름, 또는 비밀 형태 값. **제외**: `ANON_KEY`, `PUBLISHABLE_KEY`, `PUBLIC_KEY`, `pk_`                                                                                                                                    | HIGH                                 | L   | CWE-200 | A01   | M1  |
| `secret-client-bundle`   | service_role 키·`sk-` 키·개인키가 클라이언트 파일(`"use client"`, `components/`, `public/`, `src/app` 비 API 파일, `pages/` 비 API 파일)에 존재                                                                                                                                                                                                                      | CRITICAL                             | L   | CWE-798 | A07   | M1  |
| `secret-infra-config`    | `docker-compose*.yml`의 `*_PASSWORD=값`, `Dockerfile`의 `ENV`/`ARG` 키, `.github/workflows/*.yml`·`.gitlab-ci.yml`에서 `${{ secrets.X }}` 대신 평문, `vercel.json`·`netlify.toml`·`fly.toml`·`wrangler.toml`의 평문 비밀값                                                                                                                                     | HIGH                                 | L   | CWE-798 | A07   | M1  |
| `secret-dev-tool`        | `.npmrc`의 `_authToken=`, `.pypirc` 비밀번호, `.netrc`, `.docker/config.json` auth, `.vscode/launch.json`·`settings.json`의 비밀값                                                                                                                                                                                                                      | HIGH                                 | L   | CWE-798 | A07   | M1  |
| `secret-data-file`       | 커밋된 `*.sqlite`, `*.db`, `*.sql`/`*.dump`/`*.bak` 덤프, `*.log`, 출력에 토큰이 남은 `.ipynb`                                                                                                                                                                                                                                                              | MEDIUM                               | P   | CWE-538 | A01   | M1  |
| `secret-doc`             | `README.md`·`docs/*.md`·`CONTRIBUTING.md`의 실제 형식 토큰 (`curl -H "Authorization: Bearer sk-…"`)                                                                                                                                                                                                                                                   | HIGH                                 | L   | CWE-798 | A07   | M1  |
| `git-hygiene`            | `.gitignore` 없음, 또는 `.env*`·`*.pem`·`*.key`·`serviceAccountKey*.json`·`*.tfstate` 패턴 미등록 (파일이 아직 없어도 예방 차원)                                                                                                                                                                                                                                    | MEDIUM (`.env*` 미등록은 HIGH)           | L   | —       | —     | M1  |

**파일 존재형 규칙과 Git 상태**: `secret-env-file`·`secret-credential-file`·`secret-data-file`은 파일 내용 대신 파일의 Git 상태로 판정한다. 커밋됨 → 표의 심각도 그대로 · 커밋 안 됐고 ignore도 안 됨 → 한 단계 낮춤("다음 커밋에 들어갈 수 있어요") · `.gitignore`로 제외됨 → 발견 아님(검사 범위 탭에 정보로만) · Git이 아닌 폴더 → MEDIUM·Potential.

**오탐 필터 (`secrets/_filters.py`)**
| 제외 대상 | 예 |
|---|---|
| 자리표시 값 | `your-api-key-here`, `changeme`, `xxx`, `<TOKEN>`, `sk-...`, `example`, `dummy`, `test` (단, 서명 키에 쓰인 `secret`·`changeme`는 `config-weak-secret`로 잡음) |
| 환경변수 참조 | `process.env.X`, `os.environ["X"]`, `os.getenv("X")`, `import.meta.env.X`, `${X}` |
| 테스트·예제 파일 | `tests/`, `__tests__/`, `*.test.*`, `*.spec.*`, `fixtures/`, `.env.example`, `.env.sample` |
| 한국어 문장·메시지 | 오류 메시지 문자열 안의 "비밀번호" 같은 단어 |
| 낮은 엔트로피 | 이름 기반 탐지에서 길이 8 미만 또는 엔트로피 낮은 값 |

**마스킹**: 앞 4글자 + `••••`. 같은 값은 모든 출력에서 같은 마스크로 표시해 추적할 수 있게 한다 (`SecretRegistry`).

---

### WS-02 인증·인가 누락 — `analyzers/routes/`, Semgrep

| rule_id | 찾는 것 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|
| `authz-admin-route` | `/admin`·`/internal`·`/manage`·`/dashboard/admin` 라우트에 관리자 확인(`is_admin`, `role == "admin"`, `@admin_required`, `requireRole`) 단서 없음. 로그인 확인만 있어도 후보 | HIGH | P | CWE-862 | A01 | M1 |
| `authz-idor` | 경로 파라미터(`<id>`, `{id}`, `:id`) + 그 값으로 DB 조회 + 소유자 조건(`user_id == current_user.id`, `where: { userId }`) 없음 | HIGH | P | CWE-639 | A01 | M1 |
| `authz-no-auth-write` | POST·PUT·PATCH·DELETE + DB 쓰기 + 인증 가드·전역 인증 미들웨어 단서 없음. `/login`, `/signup`, `/health`, `/webhook` 제외 | HIGH | P | CWE-306 | A07 | M1 |
| `authz-csrf-exempt` | POST·PUT·PATCH·DELETE 라우트에 Django `@csrf_exempt`(`method_decorator` 포함)·Flask-WTF `@csrf.exempt`. `/webhook`·`/callback` 등 외부 호출 경로 제외 | MEDIUM | P | CWE-352 | A01 | B9 |
| `authz-jwt-no-verify` | `jwt.decode(..., options={"verify_signature": False})`, `algorithms=["none"]`, JS `jwt.decode()`만 쓰고 `jwt.verify()` 없음 | HIGH | L | CWE-347 | A04 | M1 |
| `authz-next-handler` | Next.js `app/**/route.ts`의 `GET/POST…` export, Server Action(`"use server"`)에 `auth()`·`getServerSession`·`currentUser` 단서 없음 | HIGH | P | CWE-862 | A01 | M4 |
| `authz-spring-policy` | Spring MVC 관리자 경로를 `SecurityFilterChain` 첫 일치 규칙·`@PreAuthorize`와 대조 (기존 구현 이식) | HIGH | P | CWE-862 | A01 | M4 |

**지원 라우트 인식**: Flask(`@app.route`, Blueprint), FastAPI(`@app.get`, `APIRouter`, `Depends`), Express(`app.get`, `router.post`, 미들웨어 인자) — M1 / Django(`urls.py`의 `path`·`re_path`·`include` → 함수 view·클래스 view 메서드, 가드 `@login_required`·`@permission_required`·`@user_passes_test`·`@staff_member_required`·`LoginRequiredMixin`·DRF `permission_classes`(클래스 이름으로 판정: `IsAuthenticated`는 로그인, `IsAdminUser`는 관리자, `AllowAny`는 가드 아님)·settings `MIDDLEWARE`에 들어 있는 `LoginRequiredMiddleware`, 한 view가 여러 URL에 걸리면 URL마다 판정, DRF `router.register` ViewSet(`list`·`create`·`retrieve`·`update`·`destroy`·`@action`)과 상속받은 동작으로 일하는 제네릭 뷰(`DetailView`·`UpdateView`·`DeleteView`·`CreateView`·`ListView`, DRF `generics.*APIView`·`ModelViewSet`)는 `get_queryset`·`queryset`과 상속받은 조회·저장·삭제로 판정, 저장소 안의 부모 클래스에 둔 권한도 물려받음, settings `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]`(없으면 DRF 기본값 AllowAny), 메서드는 `@require_POST`·`@require_http_methods`·`@api_view`·본문의 `request.method`/`request.POST`로 추정) — B9 / Next.js App Router — M4 / Spring MVC — M4.
**한계**: 상위 미들웨어·리버스 프록시·게이트웨이의 인증은 보지 못한다. 그래서 신뢰도는 항상 P. 관리자 단서 중 `is_staff=True`·`is_admin=True`처럼 값을 넣는 인자와 `create_superuser()`는 확인으로 보지 않는다. Django는 `path()`에 `ViewSet.as_view({...})`로 직접 건 ViewSet을 아직 라우트로 보지 않는다. 부모 클래스 권한은 깊이 우선으로 찾아 다이아몬드 상속에선 Python MRO와 다를 수 있고, `UpdateView`·`DeleteView`가 `post()`만 덮어쓰면 상속받은 GET 화면의 조회는 보지 않는다.

---

### WS-03 데이터 계층 공개 — `analyzers/baas.py`

| rule_id | 찾는 것 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|
| `baas-supabase-no-rls` | `supabase/migrations/*.sql`에서 `create table public.x` 뒤 `alter table x enable row level security` 없음 | CRITICAL | L | CWE-284 | A01 | M3 |
| `baas-supabase-open-policy` | `create policy … using (true)` / `with check (true)` | HIGH | L | CWE-284 | A01 | M3 |
| `baas-supabase-anon-grant` | `grant insert/update/delete … to anon` | HIGH | L | CWE-284 | A01 | M3 |
| `baas-supabase-definer` | `security definer` 함수에 `set search_path` 없음 | MEDIUM | L | CWE-426 | A08 | M3 |
| `baas-firebase-open` | `firestore.rules`·`storage.rules`·`database.rules.json`의 `allow read, write: if true;` | CRITICAL | L | CWE-284 | A01 | M3 |
| `baas-firebase-auth-only` | `if request.auth != null`만 있고 소유자 조건 없음 | HIGH | P | CWE-639 | A01 | M3 |

**안전 신호(억제)**: `auth.uid() = user_id`, `request.auth.uid == resource.data.ownerId`, `if false`, 관리자 claim 확인.

---

### WS-04 위험한 의존성 — `analyzers/dependencies.py`

| rule_id | 찾는 것 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|
| `dep-non-registry` | `package.json`·`requirements*.txt`·`pyproject.toml`의 `git+`, `http(s)://`, `file:`, `github:` 소스 | MEDIUM | L | CWE-829 | A08 | M4 |
| `dep-unpinned` | `*`·`latest`·범위 지정 + 잠금 파일(`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`) 없음 / `requirements.txt`에 `==` 없음 | MEDIUM | L | CWE-1357 | A03 | M4 |
| `dep-override` | `overrides`·`resolutions`가 비 레지스트리 소스로 재지정 | MEDIUM | L | CWE-829 | A08 | M4 |
| `dep-docker-latest` | `FROM python:latest`, 태그 없는 베이스 이미지 | LOW | L | CWE-1357 | A03 | M4 |
| `dep-known-vuln` | OSV에 알려진 취약 버전 — **opt-in**, 패키지 이름이 외부로 나감 | 공지 등급 따름 | L | CWE-1395 | A03 | 확장 |

---

### WS-05 입력값 주입 — Semgrep 자체 규칙 (`rules/semgrep/`)

| rule_id | 찾는 것 | 언어 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|---|
| `inject-sql` | 외부 입력·문자열 결합(f-string, `+`, `%`, `.format`, 템플릿 리터럴)이 `execute`·`query`·`raw`·`$queryRawUnsafe`, Django `.extra(where/select/order_by)`·`RawSQL`에 도달 | Py, JS/TS | HIGH | L | CWE-89 | A05 | M1 |
| `inject-code` | 외부 입력이 `eval`·`exec`·`new Function`·`vm.runInNewContext`에 도달 | Py, JS/TS | HIGH | L | CWE-94 | A05 | M1 |
| `inject-command` | 외부 입력이 `subprocess(..., shell=True)`·`os.system`·`os.popen`·`child_process.exec`에 도달 | Py, JS/TS | HIGH | L | CWE-78 | A05 | M1 |
| `inject-xss` | `Markup(입력)`, `render_template_string(입력)`, Django `mark_safe`·`SafeString`·`Template(입력)`·`HttpResponse(입력)`(`text/plain`·JSON 형식 지정은 제외), `innerHTML =`, `document.write`, `dangerouslySetInnerHTML`, `res.send(입력 포함 HTML)` | Py, JS/TS | HIGH | L | CWE-79 | A05 | M1 |
| `inject-xss-template` | `{{ x\|safe }}`, `{% autoescape false %}`, `v-html`, `{@html}`, `set:html` | 템플릿 | MEDIUM | P | CWE-79 | A05 | M1 |
| `inject-path` | 입력값으로 `open`·`send_file`·`fs.readFile`·`res.sendFile` 경로 구성 | Py, JS/TS | HIGH | L | CWE-22 | A01 | M1 |
| `inject-ssrf` | 입력 URL로 `requests`·`httpx`·`urllib`·`fetch`·`axios` 요청 | Py, JS/TS | HIGH | L | CWE-918 | A01 | M1 |
| `inject-deserialize` | `pickle.loads`, `yaml.load`(안전 로더 미지정), `marshal.loads` | Py | HIGH | P | CWE-502 | A08 | M1 |
| `inject-upload` | 업로드 파일명을 `secure_filename` 없이 저장(Django `request.FILES[..].name`을 `storage.save`에), multer `originalname` 그대로 사용 | Py, JS/TS | MEDIUM | L | CWE-434 | A06 | M1 |
| `inject-open-redirect` | `redirect(request.args[...])`, Django `HttpResponseRedirect(request.GET[...])`, `res.redirect(req.query.x)`, `window.location = 입력` | Py, JS/TS | MEDIUM | L | CWE-601 | A01 | M1 |
| `inject-java-sql-flow` | `@RequestParam`·`getParameter` → JDBC SQL 본문 (파일 간 호출 경로, 기존 구현 이식) | Java | HIGH | L | CWE-89 | A05 | M4 |

**외부 입력 출처(source)**: Flask `request.*`, FastAPI 경로·쿼리·바디 파라미터, Django `request.GET/POST/body/COOKIES/FILES/META/headers`·DRF `request.data/query_params`·view 함수(첫 인자 `request`)의 URL 인자, Express `req.body/query/params/headers`, Next.js `searchParams`·`request.json()`.
**안전 신호**: 파라미터 바인딩(`?`, `%s` + 인자 튜플, `$1`), ORM 메서드, `escape()`, `DOMPurify.sanitize`, `textContent`, `yaml.safe_load`, `secure_filename`, URL allowlist, Django `conditional_escape`·`format_html`·`reverse()`·`if url_has_allowed_host_and_scheme(url, ...):` 안의 값·`get_valid_filename`.

---

### WS-06 위험한 기본값 — `analyzers/config.py`, `analyzers/insecure_defaults.py`, Semgrep

| rule_id | 찾는 것 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|
| `config-debug` | `DEBUG = True`, `app.run(debug=True)`, `FastAPI(debug=True)`, `app.debug = True` | MEDIUM | L | CWE-489 | A02 | M1 |
| `config-allowed-hosts` | Django `ALLOWED_HOSTS = ["*"]` | MEDIUM | L | — | — | M1 |
| `config-cors-wildcard` | `CORS(app)` 기본값, `origins="*"`, `cors({ origin: '*' })`, `CORS_ALLOW_ALL_ORIGINS = True` | MEDIUM | L | CWE-942 | A02 | M1 |
| `config-cors-credentials` | `*` 또는 요청 Origin 그대로 반사 **+** `supports_credentials=True` / `credentials: true` | HIGH | L | CWE-942 | A02 | M1 |
| `config-cookie-flags` | 세션·인증 쿠키에 `Secure`·`HttpOnly`·`SameSite` 누락 (`SESSION_COOKIE_SECURE = False`, `res.cookie(..)` 옵션 누락, Django settings 어디에도 `SESSION_COOKIE_SECURE`·`CSRF_COOKIE_SECURE`가 없음 — 기본값 False라 파일 단위 발견) | MEDIUM | L | CWE-614 / 1004 / 1275 | A02 / A02 / A01 | M1 |
| `config-weak-secret` | `SECRET_KEY`·`JWT_SECRET`·`SESSION_SECRET`가 32자 미만 고정값 또는 `secret`·`changeme`·`dev` 같은 기본값, Django `startproject`의 `django-insecure-` 키 | HIGH | L | CWE-321 | A04 | M1 |
| `config-weak-hash` | 비밀번호 문맥의 `hashlib.md5`·`sha1`, `crypto.createHash('md5')`, Django `PASSWORD_HASHERS`의 `MD5`·`SHA1`·`Unsalted*`·`Crypt` hasher | MEDIUM | P | CWE-328 | A04 | M1 |
| `config-tls-verify-off` | `verify=False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | MEDIUM | L | CWE-295 | A07 | M1 |
| `config-default-credential` | 로그인 비교·시드의 `admin`/`admin`, `admin`/`password`, `root`/`root` | HIGH | L | CWE-1392 | A07 | M1 |
| `config-error-exposure` | `traceback.format_exc()`·`str(e)`·`err.stack`을 응답으로 반환 | MEDIUM | L | CWE-209 | A10 | M1 |
| `config-fail-open` | 인증·권한 함수(`*auth*`, `*permission*`, `verify*`, `is_admin`)의 `except: return True`, `catch { return next() }` | HIGH | L | CWE-636 | A10 | M1 |
| `config-swallowed-exception` | 보안 함수 안의 `except Exception: pass`, 빈 `catch {}` | LOW | P | CWE-390 | A10 | M1 |
| `config-security-todo` | 인증·권한·검증 관련 `TODO`·`FIXME`·`HACK` (점수 0) | INFO | P | — | — | M1 |

---

### WS-07 웹훅·결제 검증 누락 — `analyzers/webhooks.py`

| rule_id | 찾는 것 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|
| `webhook-unverified` | `/webhook` 경로 또는 Stripe·Toss Payments·Svix·Clerk·GitHub 웹훅 핸들러가 본문을 처리하는데 `stripe.webhooks.constructEvent`·`Webhook.verify`·HMAC `compare_digest`·서명 헤더 참조 없음 | HIGH | P | CWE-345 | A08 | M3 |
| `webhook-trusted-price` | 결제·권한 문맥(`checkout`, `payment`, `subscription`, `role`)에서 `amount`·`price`·`plan`·`role`·`isAdmin`을 요청 본문에서 그대로 사용 | HIGH | P | CWE-602 | A06 | M3 |

---

### WS-08 남용 방지 부재 — `analyzers/abuse.py`

| rule_id | 찾는 것 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|
| `abuse-no-rate-limit-auth` | `/login`·`/signup`·`/reset`·`/otp`·`/verify` 라우트 + 프로젝트 어디에도 limiter 없음 | MEDIUM | P | CWE-307 | A07 | M3 |
| `abuse-no-rate-limit-llm` | LLM SDK를 호출하는 라우트 + limiter 없음 | MEDIUM | P | CWE-770 | — (LLM10) | M3 |
| `abuse-upload-unbounded` | 업로드 핸들러 + `MAX_CONTENT_LENGTH`·multer `limits` 없음 | LOW | P | CWE-770 | — | M3 |

**안전 신호**: `flask_limiter`, `slowapi`, `express-rate-limit`, `@upstash/ratelimit`, `rate-limiter-flexible` 중 하나라도 있으면 프로젝트 단위로 억제.

---

### WS-09 LLM 연동 취약 — `analyzers/llm.py` + Semgrep

| rule_id | 찾는 것 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|
| `llm-prompt-injection` | 요청 입력이 `messages[].content`(특히 `system`)·`prompt`·`instructions`에 f-string·`+`·템플릿으로 결합 | MEDIUM | L | CWE-1427 | — (LLM01) | M3 |
| `llm-output-sink` | 모델 응답(`.choices[0].message.content`, `output_text`, `.text`)이 `eval`·`exec`·`execute`·`innerHTML`·`dangerouslySetInnerHTML`로 | CRITICAL | L | sink의 CWE (94·89·79) | A05 (LLM05) | M3 |
| `llm-client-key` | `new OpenAI({ apiKey })`가 `"use client"` 파일에 있음, `dangerouslyAllowBrowser: true` | CRITICAL | L | CWE-798 | A07 (LLM02) | M3 |

---

### WS-10 AI 에이전트 설정 오염 — `analyzers/agent.py`

| rule_id | 찾는 것 | 심각도 | 신뢰도 | CWE | OWASP | 단계 |
|---|---|---|---|---|---|---|
| `agent-allow-all` | `.claude/settings*.json`의 `bypassPermissions`·`Bash(*)`·와일드카드 허용, `--dangerously-skip-permissions` | HIGH | L | — | — (ASI02·ASI03) | M4 |
| `agent-mcp-unpinned` | `.mcp.json`·`.cursor/mcp.json`의 버전 미고정 `npx -y`·`uvx`, `curl … \| sh`, 설정 안 비밀값(마스킹) | MEDIUM | L | CWE-829 | A08 (ASI04) | M4 |
| `agent-instruction` | `CLAUDE.md`·`AGENTS.md`·`.cursorrules`·`.github/copilot-instructions.md`의 지시 무시·권한 상승·유출 지시 문구 | MEDIUM | P | — | — (ASI01) | M4 |
| `agent-hidden-text` | 지시 파일의 zero-width·bidi 제어 문자, 지시문으로 디코딩되는 base64 (디코딩은 검사용으로만) | HIGH | L | — | — (ASI01) | M4 |
| `agent-install-hook` | `package.json`의 `postinstall`·`prepare`가 원격 스크립트를 내려받아 실행 | HIGH | L | CWE-494 | A08 (ASI05) | M4 |

---

## 3. ChatGPT 보완 탐지 유형 (M3)

정적 분석으로는 패턴이 없어 찾기 어려운 위험을 ChatGPT가 검토해 찾는다 ([AI.md](AI.md) §5). ChatGPT는 아래 `vuln_type` 중에서만 고를 수 있고, 각 유형의 CWE가 정해져 있어 OWASP 코드는 카탈로그에서 자동 계산된다. 결과의 `rule_id`는 `ai-<vuln_type>`, 출처는 `AI`.

| vuln_type | 찾는 것 | WS | CWE | 심각도 상한 |
|---|---|---|---|---|
| `idor` | 로그인 사용자가 ID만 바꿔 남의 데이터를 읽거나 바꿈 (ORM·서비스 계층을 거쳐도) | WS-02 | CWE-639 | HIGH |
| `missing-authz` | 역할·권한 확인 없이 관리 기능 수행, 프론트에서만 숨긴 기능 | WS-02 | CWE-862 | CRITICAL |
| `client-trusted-identity` | 요청 본문·헤더의 `user_id`·`role`·`is_admin`을 그대로 신뢰 | WS-02 | CWE-602 | CRITICAL |
| `mass-assignment` | 요청 본문을 모델에 통째로 넣어 보호 필드(`role`, `balance` 등) 덮어쓰기 | WS-02 | CWE-915 | HIGH |
| `price-tampering` | 금액·수량·할인을 클라이언트 값으로 결제·주문 처리 | WS-07 | CWE-602 | CRITICAL |
| `state-skip` | 결제 확인 전 주문 완료 처리 등 상태 전이 건너뛰기 | WS-07 | CWE-841 | HIGH |
| `race-double-spend` | 같은 요청을 동시에 보내 쿠폰·포인트·결제를 두 번 처리 | WS-07 | CWE-362 | HIGH |
| `weak-reset-token` | 예측 가능하거나 만료·1회 사용 검증이 없는 비밀번호 재설정·인증 토큰 | WS-02 | CWE-640 | HIGH |
| `account-enumeration` | 응답 차이로 가입된 이메일·아이디가 드러남 | WS-08 | CWE-204 | MEDIUM |
| `session-fixation` | 로그인 후 세션 ID를 새로 발급하지 않음 | WS-06 | CWE-384 | MEDIUM |
| `insecure-file-access` | 다운로드·내보내기에서 다른 사용자 파일 접근 | WS-02 | CWE-639 | HIGH |
| `cross-file-injection-sql` | 다른 파일의 함수를 거쳐 입력이 SQL에 도달 | WS-05 | CWE-89 | HIGH |
| `cross-file-injection-command` | 다른 파일을 거쳐 입력이 명령 실행에 도달 | WS-05 | CWE-78 | CRITICAL |
| `cross-file-xss` | 다른 파일을 거쳐 입력이 HTML 출력에 도달 | WS-05 | CWE-79 | HIGH |
| `cross-file-path` | 다른 파일을 거쳐 입력이 파일 경로에 도달 | WS-05 | CWE-22 | HIGH |
| `llm-excessive-agency` | LLM에 DB 쓰기·명령 실행 같은 과한 도구 권한을 확인 없이 부여 | WS-09 | — (LLM06) | HIGH |
| `unsupported-lang-injection` | 정적 규칙이 없는 언어(PHP·Ruby·Go 등)의 주입 | WS-05 | CWE-74 | HIGH |
| `unsupported-lang-authz` | 정적 규칙이 없는 언어의 인가 누락 | WS-02 | CWE-862 | HIGH |

- **채택 조건** (엔진 검사): 파일이 검사 대상에 있음 · 줄 범위가 맞음 · 인용 코드가 실제 코드와 일치 · 유형이 이 표에 있음. 하나라도 어기면 폐기.
- **심각도**: ChatGPT가 제안한 값을 쓰되 위 상한을 넘지 못한다.
- **신뢰도**: 기본 Potential. 입력이 들어오는 지점부터 위험 지점까지를 인용 코드로 보여 주면 Likely.
- **설명**: 공격 시나리오(`attack_scenario_ko`), `why_ko`, `fix_ko`는 ChatGPT가 쓰고, `tech_name_ko`·`limitations_ko`는 유형별 고정 문구를 쓴다 ("ChatGPT가 코드를 읽고 판단했어요. 실행해 확인한 결과는 아니에요").
- 같은 위치·같은 CWE의 정적 분석 발견이 있으면 새 발견을 만들지 않고 그 발견에 "ChatGPT도 같은 문제를 지적" 근거를 붙인다.
- 벤치 앱에 유형별 취약·안전 표본을 두고 정밀도를 잰다.

---

## 4. 체인 상관 규칙 (M3)

같은 범위에서 **서로 다른 종류**의 신호가 겹칠 때만 체인 발견을 추가한다. 원 발견은 그대로 두고 `related`로 연결한다. 점수에는 체인만 반영한다.

| chain_id | 진입 신호 | 결과 신호 | 같은 범위 조건 | 심각도 |
|---|---|---|---|---|
| `chain-authz-inject` | `authz-no-auth-write` / `authz-admin-route` | `inject-sql` / `inject-code` / `inject-command` / `inject-path` | 결과 지점이 그 라우트 핸들러 함수 안 | CRITICAL |
| `chain-idor-enum` | `authz-idor` | `abuse-no-rate-limit-*` | 같은 라우트 | HIGH |
| `chain-secret-client` | `secret-hardcoded`(고권한 키) | `secret-client-bundle` / `secret-frontend-env` | 같은 값 지문 | CRITICAL |
| `chain-baas-open` | `baas-supabase-no-rls` / `baas-firebase-open` | 클라이언트의 anon 키 | 같은 BaaS 프로젝트 | CRITICAL |
| `chain-llm-exec` | `llm-prompt-injection` | `llm-output-sink` | 같은 함수 | CRITICAL |
| `chain-agent` | `agent-instruction` / `agent-hidden-text` | `agent-allow-all` / `agent-mcp-unpinned` / `agent-install-hook` | 같은 저장소 | HIGH |

---

## 5. 판정 규칙

### 신뢰도

| 근거 | 신뢰도 |
|---|---|
| 같은 함수 안에서 입력 → 위험 지점 흐름을 직접 확인 | Likely |
| 파일·값 자체가 증거 (커밋된 `.env`, 키 형식 리터럴) | Likely |
| 가드·설정·정책 **부재**로 추정 | Potential |
| 같은 종류 패턴이 여러 탐지기에서 겹침 | 변화 없음 |
| 체인 | 구성 발견 중 높은 쪽, 심각도 1단계 상향 |
| 정적 분석 전체 | Confirmed 없음 |

### 검사 범위 상태 (WS 10개 · OWASP 10개 각각)

| 상태 | 조건 |
|---|---|
| 취약 후보 | 열린 발견 1건 이상 |
| 검사함 · 미발견 | 관련 Analyzer 모두 정상, 해당 언어 전부 지원 |
| 부분 점검 | 일부 파일 파싱 실패, 미지원 언어 파일 포함, 또는 "부재 추정" 규칙만 해당 |
| 해당 없음 | 적용 대상 없음 (예: BaaS 파일·SDK 없음) |
| 건너뜀 | 관련 Analyzer가 실행되지 못함 (사유 표시) |
| 수동 확인 필요 | 정적 분석으로 원래 볼 수 없는 영역 (OWASP A09 등) |

### 위험 점수 (0~100)

```
risk = round(100 × (1 − Π(1 − w_sev × w_conf)))
```

| w_sev | CRITICAL 0.50 · HIGH 0.30 · MEDIUM 0.12 · LOW 0.04 · INFO 0 |
|---|---|
| **w_conf** | Likely 1.0 · Potential 0.6 |

- 열린 발견만, 같은 `rule_id`는 상위 3건만 반영
- 체인이 있으면 구성 발견 대신 체인만 반영
- 예: CRITICAL·L 1건 → 50 · HIGH·L 2건 → 51 · HIGH·P 5건 → 63

---

## 6. OWASP Top 10:2025 점검 범위

| OWASP | 관련 WS | 정적 분석 도달도 | v1 목표 상태 |
|---|---|---|---|
| A01 Broken Access Control | WS-02, WS-03, WS-05(경로·SSRF·리다이렉트), WS-01(민감 파일) | 부분 | 부분 점검 |
| A02 Security Misconfiguration | WS-06 | 부분 | 부분 점검 |
| A03 Software Supply Chain Failures | WS-04 | 부분 | 부분 점검 (M4) |
| A04 Cryptographic Failures | WS-06(서명키·해시), WS-02(JWT) | 부분 | 부분 점검 |
| A05 Injection | WS-05, WS-09 | 양호 | 검사함 |
| A06 Insecure Design | WS-05(업로드), WS-07(가격 신뢰) | 낮음 | 부분 점검 + 수동 확인 |
| A07 Authentication Failures | WS-01, WS-02, WS-06, WS-08 | 부분 | 부분 점검 |
| A08 Software or Data Integrity Failures | WS-05(역직렬화), WS-07, WS-04, WS-10 | 부분 | 부분 점검 |
| A09 Security Logging & Alerting Failures | — | 없음 | 수동 확인 필요 |
| A10 Mishandling of Exceptional Conditions | WS-06(오류 노출·fail-open) | 부분 | 부분 점검 |

**CWE → OWASP 매핑 원칙**
- `rules/catalog/owasp-top10-2025.yml`에 각 카테고리 공식 페이지의 "List of Mapped CWEs"를 **전체** 옮긴다.
- 한 CWE는 한 카테고리에만 속한다 (테스트로 확인).
- 카탈로그에 없는 CWE는 가까운 카테고리에 억지로 넣지 않고 "OWASP Top 10 범위 밖"으로 표시한다.
- 보고서 표현: "OWASP Top 10:2025 분류 기준 점검 범위". "준수·통과·안전"이라고 쓰지 않는다.

---

## 7. 규칙 메타데이터 형식

```yaml
# rules/semgrep/inject-sql.yml (발췌)
rules:
  - id: inject-sql
    languages: [python]
    severity: ERROR
    message: "외부 입력이 SQL 문자열에 결합됩니다"
    metadata:
      category: WS-05
      cwe: CWE-89
      severity: HIGH
      confidence: Likely
      title_ko: "입력값으로 DB 내용을 마음대로 꺼내거나 지울 수 있어요"
      tech_name_ko: "SQL 인젝션 (문자열 결합 쿼리)"
      why_ko: "사용자가 보낸 값이 SQL 문장 일부가 되어, 다른 사람의 데이터까지 조회·수정·삭제될 수 있어요."
      fix_ko: "값을 문자열에 붙이지 말고 파라미터 바인딩(? 또는 %s 자리표시자)으로 넘기세요."
      avoid_ko: "입력값에서 따옴표만 지우는 방식으로 막지 마세요."
      fix_example: |
        # 수정 전
        cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
        # 수정 후
        cur.execute("SELECT * FROM users WHERE name = %s", (name,))
      limitations_ko: "같은 함수 안의 흐름만 확인했습니다. 호출하는 쪽에서 값을 검증하는지는 확인하지 않았습니다."
    mode: taint
    pattern-sources: [...]
    pattern-sinks: [...]
```

```yaml
# rules/catalog/secrets.yml (발췌) — Python 탐지기 규칙도 같은 필드
- id: secret-hardcoded
  category: WS-01
  cwe: CWE-798
  severity: HIGH
  confidence: Likely
  title_ko: "비밀키가 코드에 그대로 들어 있어요"
  tech_name_ko: "하드코딩된 인증정보"
  why_ko: "저장소를 본 누구나 이 키로 외부 서비스를 쓰거나 요금을 발생시킬 수 있어요. 한 번 커밋되면 지워도 Git 기록에 남아요."
  fix_ko: "키를 바로 폐기·재발급하고, 환경변수로 옮긴 뒤 .env를 .gitignore에 추가하세요."
  avoid_ko: "코드에서 키 줄만 지우고 끝내지 마세요. 이미 노출된 키는 재발급해야 해요."
  fix_example: |
    # 수정 전
    client = OpenAI(api_key="sk-abcd...")
    # 수정 후
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
  limitations_ko: "키가 실제로 유효한지는 확인하지 않습니다."
```

**규칙 추가 체크리스트**: 메타 필드 전부 (사람 말 제목은 "~할 수 있어요"처럼 결과 중심으로) · 취약 표본 1개 이상 · 안전 표본 1개 이상 · 이 문서 표에 한 줄.

---

## 8. 기존 규칙 ID 대응 (v0.2 → v1)

기존 `WE_MEET` 코드의 규칙과 테스트 표본을 옮길 때 쓴다.

| v0.2 rule_id | v1 rule_id |
|---|---|
| `literal-token` | `secret-hardcoded` |
| `vs-secret-file` | `secret-env-file` / `secret-credential-file` |
| `weak-signing-key` | `config-weak-secret` |
| `concatenated-select`, `vs-py-sql`, `vs-js-sql`, `vs-java-sql` | `inject-sql` |
| `vs-java-sql-flow` | `inject-java-sql-flow` |
| `vs-py-code`, `vs-js-code` | `inject-code` / `inject-command` (분리) |
| `vs-py-yaml` | `inject-deserialize` |
| `vs-py-xss`, `vs-js-xss`, `unescaped-markup`, `vs-js-react-html` | `inject-xss` |
| `vs-template-raw` | `inject-xss-template` |
| `vs-py-path`, `vs-js-path` | `inject-path` |
| `vs-py-ssrf` | `inject-ssrf` |
| `vs-py-upload` | `inject-upload` |
| `vs-py-jwt`, `vs-js-jwt` | `authz-jwt-no-verify` |
| `vs-route-admin` | `authz-admin-route` |
| `vs-route-idor` | `authz-idor` |
| `vs-java-admin-policy` | `authz-spring-policy` |
| `vs-config-debug` | `config-debug` |
| `vs-config-cors`, `vs-js-cors` | `config-cors-wildcard` |
| `vs-config-cookie-flags`, `vs-js-cookie` | `config-cookie-flags` |
| `vs-js-error` | `config-error-exposure` |

---

*Last updated: 2026-11-22*
