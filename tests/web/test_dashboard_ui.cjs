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
