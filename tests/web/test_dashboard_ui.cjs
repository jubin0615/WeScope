// 대시보드 순수 로직 테스트 (Node 내장 node:test, 의존성 없음): node --test tests/web/test_dashboard_ui.cjs
const test = require("node:test");
const assert = require("node:assert/strict");
const { pathToFileURL } = require("node:url");
const path = require("node:path");

const load = (file) => import(pathToFileURL(path.join(__dirname, "../../src/wescope/web", file)).href);

test("시작 화면: 폴더 경로와 GitHub 주소 중 하나만", async () => {
  const { target } = await load("components/start.js");
  assert.deepEqual(target("  C:\app ", "", "dev"), { body: { path: "C:\app" } });          // 폴더면 브랜치 무시
  assert.deepEqual(target("", "https://github.com/o/r", ""), { body: { github: "https://github.com/o/r" } });
  assert.deepEqual(target("", "https://github.com/o/r", " dev "), { body: { github: "https://github.com/o/r", branch: "dev" } });
  assert.equal(target("C:\app", "https://github.com/o/r", "").body, undefined);
  assert.match(target("C:\app", "https://github.com/o/r", "").error, /하나만/);
  assert.deepEqual(target(" ", "", ""), { error: null });
});

const fixture = (name) => require(path.join(__dirname, "../fixtures/results", name));

test("목록: 같은 rule_id 묶기와 엔진 순서", async () => {
  const { groups } = await load("components/list.js");
  const result = fixture("first-scan.json");
  const list = groups(result.findings, "all");
  assert.equal(list.length, new Set(result.findings.map((f) => f.rule_id)).size);
  assert.equal(list[0].rule_id, result.findings[0].rule_id);
  assert.equal(list.find((g) => g.rule_id === "secret-hardcoded").findings.length, 2);
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sevs = list.map((g) => order.indexOf(g.severity));
  assert.deepEqual(sevs, [...sevs].sort((a, b) => a - b));               // 심각도 순서 유지
});

test("목록: 묶음 심각도는 가장 높은 것, 심각도 거르기는 발견 단위", async () => {
  const { groups } = await load("components/list.js");
  const { findings } = fixture("secrets-git.json");
  const env = groups(findings, "all").find((g) => g.rule_id === "secret-env-file");
  assert.equal(env.severity, "CRITICAL");
  assert.equal(env.findings.length, 2);
  const high = groups(findings, "all", "HIGH").find((g) => g.rule_id === "secret-env-file");
  assert.deepEqual(high.findings.map((f) => f.location.file), [".env.local"]);
});

test("탭: FIXED·오탐은 전체에서 빠지고 각 탭에만", async () => {
  const { groups, tabCounts } = await load("components/list.js");
  const result = fixture("rescan-new-fixed-dismissed.json");
  const ids = (tab) => groups(result.findings, tab).flatMap((g) => g.findings.map((f) => f.id));
  assert.deepEqual(ids("fixed"), ["F-024"]);
  assert.deepEqual(ids("dismissed").sort(), ["F-006", "F-023"]);
  assert.deepEqual(ids("new"), ["F-016"]);
  for (const id of ["F-024", "F-006", "F-023"]) assert.ok(!ids("all").includes(id), id);
  assert.equal(tabCounts(result.findings).ai, 0);
});

test("요약 숫자와 전체 탭이 같은 발견을 센다 (샘플 6개)", async () => {
  const { groups } = await load("components/list.js");
  for (const name of ["clean.json", "first-scan.json", "rescan-new-fixed-dismissed.json", "secrets-git.json", "semgrep-skipped.json", "with-fix.json"]) {
    const result = fixture(name);
    for (const [sev, count] of Object.entries(result.summary.severity)) {
      const shown = groups(result.findings, "all", sev).reduce((n, g) => n + g.findings.length, 0);
      assert.equal(shown, count, `${name} ${sev}`);
    }
  }
});

test("선택 유지: 같은 rule_id가 있으면 그대로, 없으면 첫 묶음", async () => {
  const { groups, keepSelection } = await load("components/list.js");
  const list = groups(fixture("first-scan.json").findings, "all");
  assert.equal(keepSelection(list, "inject-sql"), "inject-sql");
  assert.equal(keepSelection(list, "gone"), list[0].rule_id);
  assert.equal(keepSelection([], "inject-sql"), null);
});

test("위치 표기: 라우트 > 파일:줄 > 파일", async () => {
  const { where } = await load("components/list.js");
  assert.equal(where({ location: { file: "app.py", line: 41, route: "GET /orders/<id>" } }), "GET /orders/<id>");
  assert.equal(where({ location: { file: "app.py", line: 36, route: null } }), "app.py:36");
  assert.equal(where({ location: { file: ".env", line: 0, route: null } }), ".env");
});

test("상태 문장 시각: 방금 · n분 전 · n시간 전 · 날짜", async () => {
  const { relTime } = await load("components/topbar.js");
  const now = new Date(2026, 10, 25, 15, 0).getTime();
  const ago = (ms) => new Date(now - ms).toISOString();
  assert.equal(relTime(ago(30e3), now), "방금");
  assert.equal(relTime(ago(3 * 60e3), now), "3분 전");
  assert.equal(relTime(ago(5 * 3600e3), now), "5시간 전");
  assert.equal(relTime(new Date(2026, 10, 20, 9, 5).toISOString(), now), "11월 20일 09:05");
});

test("프롬프트: 근거 코드(비밀값 조각)를 넣지 않는다 — canary 0건", async () => {
  const { groups } = await load("components/list.js");
  const { buildPrompt } = await load("components/prompt.js");
  const result = structuredClone(fixture("secrets-git.json"));
  result.findings.forEach((f, i) => { f.evidence = `KEY="sk_live_CANARY${i}"`; });
  const repo = { name: "landing-page", branch: "main" };
  for (const group of groups(result.findings, "all")) {
    const text = buildPrompt({ repo, result, group });
    assert.doesNotMatch(text, /CANARY/, group.rule_id);
    assert.match(text, /발급처에서 폐기·재발급/);                          // WS-01 묶음
  }
});

test("프롬프트: 형식 — 프로젝트·문제·위치(10곳까지)·수정 방법", async () => {
  const { groups } = await load("components/list.js");
  const { buildPrompt } = await load("components/prompt.js");
  const result = structuredClone(fixture("first-scan.json"));
  const sql = groups(result.findings, "all").find((g) => g.rule_id === "inject-sql");
  const text = buildPrompt({ repo: { name: "shop", branch: null }, result, group: sql });
  assert.match(text, /^\[We-Scope 보안 수정 요청\]\n프로젝트: shop\n문제: SQL 인젝션.* — HIGH · CWE-89 · OWASP A05:2025\n위치: app\.py:36\n/);
  assert.match(text, /수정 예시:\n```\n/);
  assert.doesNotMatch(text, /발급처/);                                    // WS-01이 아니면 없음
  const many = { ...sql, findings: Array.from({ length: 12 }, (_, i) => ({ ...sql.findings[0], location: { file: "a.py", line: i + 1, route: null } })) };
  assert.match(buildPrompt({ repo: { name: "shop" }, result, group: many }), /위치: a\.py:1, .*a\.py:10 외 2곳\n/);
});

test("프롬프트: 수정안이 있으면 검증 상태와 diff·코드 밖에서 할 일", async () => {
  const { groups } = await load("components/list.js");
  const { buildPrompt } = await load("components/prompt.js");
  const result = fixture("with-fix.json");
  const list = groups(result.findings, "all");
  const weak = list.find((g) => g.rule_id === "config-weak-secret");
  const text = buildPrompt({ repo: { name: "shop" }, result, group: weak });
  assert.match(text, /\n제안 수정 \(We-Scope 검증됨: 적용·문법·재검사 통과\):\n```diff\n--- a\/app\.py\n/);
  assert.doesNotMatch(text, /수정 방법:/);
  assert.match(text, /\n코드 밖에서 할 일: .+ \/ .+\n확인: /);
  const failed = buildPrompt({ repo: { name: "shop" }, result, group: list.find((g) => g.rule_id === "inject-command") });
  assert.match(failed, /제안 수정 \(검증 안 됨: 참고용\):/);
  assert.doesNotMatch(failed, /코드 밖에서 할 일/);                      // follow_ups가 비면 줄째 생략
  const none = buildPrompt({ repo: { name: "shop" }, result, group: list.find((g) => g.rule_id === "inject-sql") });
  assert.match(none, /\n수정 방법: /);
});

test("목록: 수정안 검증 상태와 AI 탭 (ChatGPT가 찾음 · 확인함)", async () => {
  const { groups, groupFix, VERIFY, tags } = await load("components/list.js");
  const { findings } = fixture("with-fix.json");
  const all = groups(findings, "all");
  assert.equal(VERIFY[groupFix(all.find((g) => g.rule_id === "config-weak-secret")).verification][0], "✓ 검증됨");
  assert.equal(groupFix(all.find((g) => g.rule_id === "inject-sql")), null);
  assert.deepEqual(groups(findings, "ai").map((g) => g.rule_id), ["ai-price-tampering", "authz-idor"]);
  assert.deepEqual(tags(all[0], "all", true), ["AI"]);
});

test("진행 표시: ChatGPT 단계와 진행 수", async () => {
  const { progressLabel, STAGES } = await load("components/topbar.js");
  assert.deepEqual(STAGES.map(([k]) => k), ["collect", "analyze", "organize", "ai", "save"]);
  assert.equal(progressLabel({ status: "queued", stage: null }), "대기 중…");
  assert.equal(progressLabel({ status: "running", stage: "analyze", ai_progress: null }), "정적 분석 중…");
  assert.equal(progressLabel({ status: "running", stage: "ai", ai_progress: { task: "fix", done: 3, total: 5 } }), "ChatGPT 분석 중… 수정안 3/5");
  assert.equal(progressLabel({ status: "running", stage: "ai", ai_progress: null }), "ChatGPT 분석 중…");
});

test("diff 줄 색과 설정 창 제외 패턴 정리", async () => {
  const { diffClass } = await load("components/detail.js");
  assert.deepEqual(["--- a/app.py", "+++ b/app.py", "@@ -1 +1 @@", "-old", "+new", " same"].map(diffClass),
    ["diff-file", "diff-file", "diff-hunk", "diff-remove", "diff-add", ""]);
  const { parseLines } = await load("components/settings.js");
  assert.deepEqual(parseLines(" dist/ \r\n\n*.min.js\n  "), ["dist/", "*.min.js"]);
});

test("수정안: 심각도 거르기로 대표 발견이 빠져도 규칙의 수정안을 찾는다", async () => {
  const { groups, groupFix } = await load("components/list.js");
  const result = structuredClone(fixture("secrets-git.json"));
  const env = result.findings.filter((f) => f.rule_id === "secret-env-file");
  assert.deepEqual(env.map((f) => f.severity), ["CRITICAL", "HIGH"]);
  env[0].fix = { verification: "verified", diff: "--- a/x\n+++ b/x\n" };            // 서버는 대표(첫) 발견에 붙인다
  const high = groups(result.findings, "all", "HIGH").find((g) => g.rule_id === "secret-env-file");
  assert.deepEqual(high.findings.map((f) => f.severity), ["HIGH"]);                  // 보이는 위치는 거른 그대로
  assert.equal(groupFix(high)?.verification, "verified");
});
