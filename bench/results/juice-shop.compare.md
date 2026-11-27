# juice-shop 비교 결과

- 커밋 `c9f99228d9d56afb5f5ca7925376292f7fa44b13` · 검사한 파일 1491개 · 걸린 시간 51.2초
- 정적 탐지 가능 항목 42개 중 12개 찾음 (탐지율 29%); 챌린지·실습 근거 항목만 보면 40개 중 11개
- We-Scope 발견 113개 = 정답지 일치 25 + 정답지 밖 실제 문제 9 + 오탐 58 + 예제·테스트 코드 21 → 정밀도 37% (예제·테스트까지 오탐으로 치면 30%)

## 정답지 항목

| id | 취약점 | 위치 | CWE | OWASP 2025 | 구분 | 결과 | 근거·이유 |
|---|---|---|---|---|---|---|---|
| JS-01 | 로그인 SQL 문자열 결합 | `routes/login.ts:34` | CWE-89 | A05:2025 | 정적 탐지 가능 | 찾음 | inject-sql login.ts:34 |
| JS-02 | 상품 검색 SQL 문자열 결합 | `routes/search.ts:23` | CWE-89 | A05:2025 | 정적 탐지 가능 | 찾음 | inject-sql search.ts:23 |
| JS-06 | 사용자 이름 #{...}를 eval | `routes/userProfile.ts:65` | CWE-94 | A05:2025 | 정적 탐지 가능 | 찾음 | inject-code userProfile.ts:65 |
| JS-14 | 프로필 이미지 URL을 서버가 fetch | `routes/profileImageUrlUpload.ts:24` | CWE-918 | A01:2025 | 정적 탐지 가능 | 찾음 | inject-ssrf profileImageUrlUpload.ts:24 |
| JS-21 | JWT RSA 개인키 하드코딩 | `lib/insecurity.ts:21` | CWE-321 | A04:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded insecurity.ts:21 |
| JS-27 | 시드 데이터에 평문 비밀번호 (admin123 등) | `data/static/users.yml:3` | CWE-798 | A07:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded users.yml:107, secret-hardcoded users.yml:115, secret-hardcoded users.yml:123, secret-hardcoded users.yml:141, secret-hardcoded users.yml:150, secret-hardcoded users.yml:151, secret-hardcoded users.yml:239, secret-hardcoded users.yml:277, secret-hardcoded users.yml:296, secret-hardcoded users.yml:3, secret-hardcoded users.yml:31, secret-hardcoded users.yml:63, secret-hardcoded users.yml:88 |
| JS-28 | 2FA TOTP 비밀값 평문 저장 | `data/static/users.yml:151` | CWE-312 | A06:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded users.yml:150, secret-hardcoded users.yml:151 |
| JS-29 | premium.key 커밋 | `encryptionkeys/premium.key` | CWE-540 | A01:2025 | 정적 탐지 가능 | 찾음 | secret-credential-file premium.key:0 |
| JS-30 | Terraform에 RSA 개인키 | `infrastructure/terraform/networking.tf:171` | CWE-798 | A07:2025 | 정적 탐지 가능 | 찾음 | secret-hardcoded networking.tf:171 |
| JS-31 | 개발자 백업 파일 ftp/package.json.bak | `ftp/package.json.bak` | CWE-530 | - | 정적 탐지 가능 | 찾음 | secret-data-file package.json.bak:0 |
| JS-32 | 영업 백업 파일 ftp/coupons_2013.md.bak | `ftp/coupons_2013.md.bak` | CWE-530 | - | 정적 탐지 가능 | 찾음 | secret-data-file coupons_2013.md.bak:0 |
| JS-40 | 토큰 쿠키에 SameSite 없음 + 프로필 변경이 쿠키 인증 (CSRF) | `routes/updateUserProfile.ts:42` | CWE-352 | A01:2025 | 정적 탐지 가능 | 찾음 | config-cookie-flags insecurity.ts:192, config-cookie-flags updateUserProfile.ts:42 |
| JS-03 | 리뷰 조회 MongoDB $where에 입력 결합 | `routes/showProductReviews.ts:36` | CWE-943 | - | 정적 탐지 가능 | 놓침 | 규칙 없음 — NoSQL($where) 주입 sink가 없음 |
| JS-04 | 주문 추적 MongoDB $where에 입력 결합 | `routes/trackOrder.ts:18` | CWE-943 | - | 정적 탐지 가능 | 놓침 | 규칙 없음 — NoSQL($where) 주입 sink가 없음 |
| JS-05 | 리뷰 수정 조건에 req.body.id 그대로 (연산자 주입·multi) | `routes/updateProductReviews.ts:18` | CWE-943 | - | 정적 탐지 가능 | 놓침 | 규칙 없음 — MongoDB 조건 객체에 입력을 그대로 넣는 패턴 없음 |
| JS-07 | B2B 주문 입력을 vm.runInContext(safeEval)로 실행 | `routes/b2bOrder.ts:23` | CWE-94 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음(vm.runInContext는 목록에 없음) + source 미인식(({ body }) 구조 분해) |
| JS-08 | 검색어를 bypassSecurityTrustHtml (DOM XSS) | `frontend/src/app/search-result/search-result.component.ts:146` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — Angular bypassSecurityTrustHtml을 XSS sink로 보지 않음 |
| JS-09 | 상품 설명을 bypassSecurityTrustHtml | `frontend/src/app/search-result/search-result.component.ts:113` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — Angular bypassSecurityTrustHtml |
| JS-10 | 주문 번호를 bypassSecurityTrustHtml | `frontend/src/app/track-result/track-result.component.ts:49` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — Angular bypassSecurityTrustHtml |
| JS-11 | true-client-ip 헤더 저장 후 bypassSecurityTrustHtml | `frontend/src/app/last-login-ip/last-login-ip.component.ts:40` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — Angular bypassSecurityTrustHtml (헤더 저장과 출력이 다른 파일) |
| JS-12 | 피드백 댓글을 bypassSecurityTrustHtml (서버는 sanitize-html 1.4.2) | `frontend/src/app/about/about.component.ts:120` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — Angular bypassSecurityTrustHtml |
| JS-13 | 관리자 화면에서 사용자 이메일을 bypassSecurityTrustHtml | `frontend/src/app/administration/administration.component.ts:74` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — Angular bypassSecurityTrustHtml |
| JS-15 | zip 항목 이름으로 파일 쓰기 (Zip Slip) | `routes/fileUpload.ts:34` | CWE-22 | A01:2025 | 정적 탐지 가능 | 놓침 | source 미인식 — zip 항목 이름(entry.path)을 외부 입력으로 보지 않음 |
| JS-16 | res.render에 req.body 펼침 (layout으로 임의 파일 읽기) | `routes/dataErasure.ts:107` | CWE-22 | A01:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — res.render 옵션에 req.body를 펼치는 패턴 |
| JS-17 | XML 파서 XML_PARSE_NOENT·DTDLOAD (XXE) | `lib/xml.ts:35` | CWE-611 | A02:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — XXE(외부 엔티티 허용 파서 옵션) 규칙이 없음 |
| JS-18 | 리다이렉트 허용 목록을 includes()로 비교 | `routes/redirect.ts:18` | CWE-601 | A01:2025 | 정적 탐지 가능 | 놓침 | source 미인식 — ({ query }: Request) 구조 분해라 req.query로 보지 않음 |
| JS-19 | /ftp 디렉터리 목록 공개 (serve-index) | `server.ts:294` | CWE-548 | A01:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — 디렉터리 목록(serve-index) 노출 규칙이 없음 |
| JS-20 | /support/logs 로그 디렉터리 공개 | `server.ts:306` | CWE-532 | A09:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — 디렉터리 목록(serve-index) 노출 규칙이 없음 |
| JS-22 | HMAC 키 하드코딩 | `lib/insecurity.ts:44` | CWE-798 | A07:2025 | 정적 탐지 가능 | 놓침 | 변수 이름 없이 createHmac 인자에 바로 쓴 문자열이라 비밀값으로 보지 않음 |
| JS-23 | 비밀번호를 MD5로 해시 | `lib/insecurity.ts:43` | CWE-328 | A04:2025 | 정적 탐지 가능 | 놓침 | 약한 해시는 앞뒤 3줄에 password 단어가 있어야 잡음 (hash 함수가 따로 정의됨) |
| JS-24 | 진행 코드 Hashids salt 하드코딩 | `routes/continueCode.ts:13` | CWE-321 | A04:2025 | 정적 탐지 가능 | 놓침 | Hashids 생성자 인자의 salt를 비밀값으로 보지 않음 |
| JS-26 | 로그인 화면 코드에 테스트 계정 비밀번호 | `frontend/src/app/login/login.component.ts:73` | CWE-798 | A07:2025 | 정적 탐지 가능 | 놓침 | 값에 'Testing'이 들어 있어 자리표시자(test)로 보고 버림 |
| JS-33 | jws.verify에 알고리즘 고정 없음 + express-jwt 0.1.3 (alg none·키 혼동) | `lib/insecurity.ts:55` | CWE-347 | A04:2025 | 정적 탐지 가능 | 놓침 | jwt.decode 없이 jws.verify만 씀 — 알고리즘 고정 누락은 규칙이 보지 않음 |
| JS-35 | errorhandler()로 스택 트레이스 노출 | `server.ts:722` | CWE-209 | A10:2025 | 정적 탐지 가능 | 놓침 | errorhandler() 미들웨어 사용은 패턴에 없음 (err.stack·message 반환만 봄) |
| JS-36 | PUT /api/Products/:id 인증 미들웨어 주석 처리 (finale-rest 자동 API) | `server.ts:402` | CWE-862 | A01:2025 | 정적 탐지 가능 | 놓침 | finale-rest 자동 REST API는 라우트로 인식하지 않음 |
| JS-37 | /metrics 인증 없이 공개 | `server.ts:771` | CWE-200 | A01:2025 | 정적 탐지 가능 | 놓침 | /metrics는 관리자 경로로 보지 않음, 읽기 라우트 인증 누락 규칙 없음 |
| JS-38 | 비밀번호 재설정 속도 제한 키를 X-Forwarded-For 헤더로 | `server.ts:378` | CWE-348 | - | 정적 탐지 가능 | 놓침 | 규칙 없음 — 신뢰할 수 없는 프록시 헤더로 속도 제한 키를 만드는 패턴 |
| JS-39 | 현재 사용자 정보를 JSONP(callback)로 응답 | `routes/currentUser.ts:58` | CWE-200 | A01:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — JSONP 응답 |
| JS-41 | 업로드한 YAML을 js-yaml 3.x load (메모리 폭탄) | `routes/fileUpload.ts:114` | CWE-776 | A02:2025 | 정적 탐지 가능 | 놓침 | yaml.load가 vm.runInContext 문자열 안에 있어 호출로 보이지 않음 (js-yaml 3.x) |
| JS-42 | 사용자 이름을 pug 템플릿 문자열에 넣어 compile, CSP에 profileImage 결합 | `routes/userProfile.ts:73` | CWE-79 | A05:2025 | 정적 탐지 가능 | 놓침 | sink 없음 — 문자열로 만든 pug 템플릿을 compile |
| JS-43 | /infrastructure IaC 파일 디렉터리 공개 | `server.ts:273` | CWE-548 | A01:2025 | 정적 탐지 가능 | 놓침 | 규칙 없음 — 디렉터리 목록(serve-index) 노출 규칙이 없음 |
| JS-44 | 장바구니 조회가 :id만으로 (소유자 확인 없음) | `routes/basket.ts:19` | CWE-639 | A01:2025 | 정적 탐지 가능 | 놓침 | 라우트(server.ts)와 처리 함수(routes/basket.ts)가 다른 파일이라 본문을 보지 못함 |
| JS-L01 | fields 파라미터로 비밀번호 해시까지 응답 | `routes/currentUser.ts:30` | CWE-213 | - | 업무 로직 | 업무 로직 |  |
| JS-L02 | 회원가입 시 role을 요청 본문에서 받음 (대량 할당) | `server.ts:550` | CWE-915 | A08:2025 | 업무 로직 | 업무 로직 |  |
| JS-L03 | CAPTCHA 답을 재사용 가능 | `routes/captcha.ts` | CWE-804 | - | 업무 로직 | 업무 로직 |  |
| JS-L04 | 현재 비밀번호 없이 GET으로 비밀번호 변경 | `routes/changePassword.ts` | CWE-620 | A07:2025 | 업무 로직 | 업무 로직 |  |
| JS-L05 | 폐기된 B2B XML 업로드 경로가 살아 있음 | `routes/fileUpload.ts:76` | CWE-1059 | - | 업무 로직 | 업무 로직 |  |
| JS-L06 | 확장자 검사 뒤 %00 잘라내기 (Poison Null Byte) | `routes/fileServer.ts:27` | CWE-158 | - | 업무 로직 | 업무 로직 |  |
| JS-L07 | 빈 이메일·비밀번호로 가입 | `models/user.ts` | CWE-20 | A05:2025 | 업무 로직 | 업무 로직 |  |
| JS-L08 | 쿠폰 만료를 클라이언트 시각(orderDetails)으로 판단 | `routes/order.ts` | CWE-602 | A06:2025 | 업무 로직 | 업무 로직 |  |
| JS-L09 | 피드백 삭제 권한 확인 부족 | `server.ts:393` | CWE-285 | A01:2025 | 업무 로직 | 업무 로직 |  |
| JS-L10 | 쿠폰이 비밀 없는 z85 인코딩 | `lib/insecurity.ts` | CWE-327 | A04:2025 | 업무 로직 | 업무 로직 |  |
| JS-L11 | 피드백 작성자 UserId를 본문에서 받음 | `routes/verify.ts:31` | CWE-639 | A01:2025 | 업무 로직 | 업무 로직 |  |
| JS-L12 | 리뷰 작성자·수정 대상 소유자 확인 없음 | `routes/updateProductReviews.ts:16` | CWE-639 | A01:2025 | 업무 로직 | 업무 로직 |  |
| JS-L13 | 데이터 내보내기가 이메일 비교를 느슨하게 | `routes/dataExport.ts` | CWE-639 | A01:2025 | 업무 로직 | 업무 로직 |  |
| JS-L14 | OAuth 사용자 비밀번호가 이메일 역순 base64 | `frontend/src/app/oauth/oauth.component.ts` | CWE-640 | A07:2025 | 업무 로직 | 업무 로직 |  |
| JS-L15 | 장바구니 항목 BasketId 파라미터 오염 | `routes/basketItems.ts:45` | CWE-235 | A10:2025 | 업무 로직 | 업무 로직 |  |
| JS-L16 | 좋아요 경쟁 조건 | `routes/likeProductReviews.ts` | CWE-362 | A06:2025 | 업무 로직 | 업무 로직 |  |
| JS-L17 | 허용 목록에 더 안 쓰는 암호화폐 주소 | `lib/insecurity.ts:124` | CWE-601 | A01:2025 | 업무 로직 | 업무 로직 |  |
| JS-L18 | 음수 수량 주문 | `routes/order.ts:144` | CWE-20 | A05:2025 | 업무 로직 | 업무 로직 |  |
| JS-L19 | 비밀번호 확인란 검증을 서버가 안 함 | `models/user.ts` | CWE-20 | A05:2025 | 업무 로직 | 업무 로직 |  |
| JS-L20 | 업로드 크기 제한이 클라이언트에만 | `routes/fileUpload.ts:57` | CWE-434 | A06:2025 | 업무 로직 | 업무 로직 |  |
| JS-L21 | 업로드 형식 제한이 클라이언트에만 | `routes/fileUpload.ts:65` | CWE-434 | A06:2025 | 업무 로직 | 업무 로직 |  |
| JS-L22 | 자막 파일 내용을 script 태그에 그대로 | `routes/videoHandler.ts:69` | CWE-79 | A05:2025 | 업무 로직 | 업무 로직 |  |
| JS-L23 | 별점 0 피드백 허용 | `models/feedback.ts:59` | CWE-20 | A05:2025 | 업무 로직 | 업무 로직 |  |
| JS-L24 | 결제 수단 없이 Deluxe 가입 | `routes/deluxe.ts:44` | CWE-840 | - | 업무 로직 | 업무 로직 |  |
| JS-L25 | 챗봇이 할인율을 도구 인자로 정함 (서버 상한 없음) | `routes/chat.ts:180` | CWE-1426 | - | 업무 로직 | 업무 로직 |  |
| JS-L26 | 챗봇 디버그 정보를 일반 사용자에게 | `routes/chat.ts:222` | CWE-200 | A01:2025 | 업무 로직 | 업무 로직 |  |
| JS-L27 | Passkey 서명 검증 우회 | `routes/passkey.ts:222` | CWE-347 | A04:2025 | 업무 로직 | 업무 로직 |  |
| JS-L28 | Passkey 공개키 덮어쓰기 | `routes/passkey.ts:142` | CWE-639 | A01:2025 | 업무 로직 | 업무 로직 |  |
| JS-R01 | 관리자 화면 경로가 프런트 라우팅에만 숨겨짐 | `frontend/src/app/app.routing.ts:80` | - | - | 정적 불가(런타임·OSINT) | 정적 불가(런타임·OSINT) |  |
| JS-R02 | 숨겨진 프런트 경로 찾기 | `frontend/src/app/app.routing.ts` | - | - | 정적 불가(런타임·OSINT) | 정적 불가(런타임·OSINT) |  |
| JS-R03 | 보안 질문 답을 OSINT로 추측 | - | - | - | 정적 불가(런타임·OSINT) | 정적 불가(런타임·OSINT) |  |
| JS-R04 | 유출·추측 가능한 사용자 비밀번호로 로그인 | - | - | - | 정적 불가(런타임·OSINT) | 정적 불가(런타임·OSINT) |  |
| JS-R05 | 공개 자료·사이트 탐색으로 찾는 것 | - | - | - | 정적 불가(런타임·OSINT) | 정적 불가(런타임·OSINT) |  |
| JS-U01 | 의존성·공급망 취약점 (SCA) | `package.json` | - | - | 지원 범위 밖 | 지원 범위 밖 |  |
| JS-U02 | 취약한 컨테이너 이미지 mongo:4.4.29 | `infrastructure/docker-compose.yml:59` | - | - | 지원 범위 밖 | 지원 범위 밖 |  |
| JS-U03 | Solidity 스마트 컨트랙트 | `data/static/web3-snippets/HoneyPotNFT.sol` | - | - | 지원 범위 밖 | 지원 범위 밖 |  |

## 정답지 밖 발견 판정

| 판정 | 규칙 | 개수 | 예 | 이유 |
|---|---|---|---|---|
| 실제 문제 | authz-admin-route | 2 | `server.ts:645` | /rest/admin/application-version·configuration이 인증 없이 버전·설정을 노출 (알려진 취약 라이브러리 찾기에 쓰임) |
| 실제 문제 | config-cors-wildcard | 2 | `server.ts:184` | 모든 출처 CORS 허용 |
| 실제 문제 | secret-credential-file | 1 | `ctf.key:0` | CTF 플래그 HMAC 키가 저장소에 있음 |
| 실제 문제 | git-hygiene | 1 | `.gitignore:0` | .gitignore에 비밀 파일 패턴이 없음 (권고) |
| 실제 문제 | config-weak-secret | 1 | `server.ts:321` | cookieParser('kekse') 쿠키 서명 비밀이 짧은 고정값 |
| 실제 문제 | secret-data-file | 1 | `ftp/package-lock.json.bak:0` | 공개 ftp 폴더의 백업 파일 |
| 실제 문제 | config-error-exposure | 1 | `lib/utils.ts:251` | getErrorMessage가 error.message를 여러 API 응답에 그대로 보냄 |
| 오탐 | secret-hardcoded | 51 | `frontend/src/assets/i18n/bn_BD.json:10` | "LABEL_PASSWORD": "Password" 같은 화면 번역 문구 |
| 오탐 | config-security-todo | 3 | `frontend/src/assets/private/three.js:28328` | three.js 라이브러리·타입 정의 FIXME·안내 문구 TODO로 보안 조치가 빠진 곳이 아님 |
| 오탐 | inject-path | 2 | `routes/vulnCodeFixes.ts:83` | key가 실제 챌린지 키일 때만 파일을 읽음 (없으면 404) |
| 오탐 | authz-jwt-no-verify | 1 | `routes/authenticatedUsers.ts:20` | 서버가 발급해 보관한 토큰에서 iat만 읽음, 인증 판단에 쓰지 않음 |
| 오탐 | inject-path | 1 | `routes/profileImageFileUpload.ts:42` | 경로가 로그인 사용자 id와 파일 형식 감지 결과로만 만들어짐 |
| 예제·테스트 | config-weak-secret | 8 | `data/static/codefixes/accessLogDisclosureChallenge_1_correct.ts:24` | 코딩 챌린지용 예제 코드 (실행 안 됨) |
| 예제·테스트 | config-default-credential | 8 | `test/cypress/e2e/b2bOrder.spec.ts:6` | 테스트 코드의 테스트 계정·TODO |
| 예제·테스트 | inject-sql | 4 | `data/static/codefixes/dbSchemaChallenge_1.ts:5` | 코딩 챌린지용 예제 코드 (실행 안 됨) |
| 예제·테스트 | config-security-todo | 1 | `test/cypress/e2e/basket.spec.ts:51` | 테스트 코드의 테스트 계정·TODO |
