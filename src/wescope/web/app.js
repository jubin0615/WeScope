// 상태·API·SSE·화면 조립. 화면은 ScanResult JSON과 ARCHITECTURE.md §7-1 API만 쓴다.
import { h, SEVERITIES } from "./dom.js";
import { renderStart } from "./components/start.js";
import { renderTopbar, renderProgress } from "./components/topbar.js";
import { renderSummary } from "./components/summary.js";
import { renderTabs } from "./components/tabs.js";
import { TABS, groups, tabCounts, keepSelection, renderList } from "./components/list.js";
import { renderDetail } from "./components/detail.js";
import { renderCoverage } from "./components/coverage.js";

const root = document.getElementById("app");
const OFFLINE = "서버와 연결이 끊겼어요. 터미널에서 wescope를 다시 실행하세요.";
const EMPTY = {
  new: "직전 검사보다 새로 생긴 위험 후보가 없어요",
  fixed: "직전 검사 뒤에 사라진 위험 후보가 없어요",
  ai: "ChatGPT가 찾거나 확인한 위험 후보가 없어요",
  dismissed: "오탐으로 표시한 항목이 없어요",
  all: "이 심각도의 위험 후보가 없어요",
};

const state = {
  repos: [], repoId: null, result: null, jobs: {}, failed: null, offline: false, selected: null, latestScan: null,
  names: { ws: {}, owasp: {} },   // GET /api/catalog: 코드값 → 이름. 못 받으면 코드만 보인다
  ...loadView(),
};
const parts = {};     // 다시 그릴 때 유지하는 영역 (목록 스크롤 위치 보존)
const sources = {};   // 프로젝트별로 지켜보는 검사의 SSE. 다른 프로젝트 검사를 시작해도 앞선 검사를 놓치지 않는다

// 실패하면 서버의 {"detail"} 문장을 그대로 던진다. 서버에 닿지 못하면 offline 표시를 붙인다.
export async function api(path, { method = "GET", body } = {}) {
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw Object.assign(new Error(OFFLINE), { offline: true });
  }
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.detail || `요청이 실패했어요 (${response.status})`);
  return data;
}

// 고른 탭·심각도는 새로고침해도 유지. shortcut: 브라우저 localStorage, 전역 설정 API가 생기면 옮긴다 (DASHBOARD.md §8-2)
function loadView() {
  try {
    const saved = JSON.parse(localStorage.getItem("wescope.view")) || {};
    return { tab: [...TABS, "coverage"].includes(saved.tab) ? saved.tab : "all", severity: SEVERITIES.includes(saved.severity) ? saved.severity : null };
  } catch {
    return { tab: "all", severity: null };
  }
}
function saveView() {
  try { localStorage.setItem("wescope.view", JSON.stringify({ tab: state.tab, severity: state.severity })); } catch { /* 저장 못 해도 화면은 동작 */ }
}

const repo = () => state.repos.find((r) => r.id === state.repoId);
const jobHere = () => state.jobs[state.repoId] ?? null;
const visibleTabs = (result) => [
  ...TABS.filter((t) => ((t !== "new" && t !== "fixed") || result.baseline_scan) && (t !== "ai" || result.ai)),
  "coverage"];

// ---------- 그리기 ----------

function render() {
  if (!state.repos.length) return renderStart(root, { api, onStarted: (data) => guard(() => started(data)) });
  parts.top = h("header", { className: "topbar" });
  renderTop();
  root.replaceChildren(parts.top, ...(state.result ? dashboard(state.result) : firstScan()));
}

function renderTop() {
  if (parts.top?.querySelector("details[open]")) return;   // 프로젝트 메뉴를 보는 중이면 닫지 않는다
  renderTopbar(parts.top,
    { repos: state.repos, repo: repo(), result: state.result, job: jobHere(), failed: state.failed, offline: state.offline },
    { selectRepo: (id) => guard(() => selectRepo(id)), addRepo, rescan: () => guard(rescan), openCoverage: () => setTab("coverage") });
}

function firstScan() {
  const job = jobHere();
  if (job) {
    return [h("section", { className: "center panel" }, renderProgress(job),
      h("p", { className: "muted", textContent: "처음 검사는 프로젝트 크기에 따라 수십 초 걸릴 수 있어요" }))];
  }
  const retry = h("button", { type: "button", className: "btn btn-primary", textContent: "검사 시작", disabled: state.offline });
  retry.addEventListener("click", () => guard(rescan));
  return [h("section", { className: "center panel" },
    h("p", { className: state.failed ? "status-bad" : "", textContent: state.failed ? `검사하지 못했어요: ${state.failed}` : "아직 검사 결과가 없어요" }),
    retry)];
}

function dashboard(result) {
  const visible = visibleTabs(result);
  const tab = visible.includes(state.tab) ? state.tab : "all";
  // 저장된 거르기가 이 결과에 없는 심각도면 무시 (0인 버튼은 꺼져 있어 풀 수 없으므로)
  const severity = result.summary.severity[state.severity] ? state.severity : null;
  const summary = h("div", { className: "summary" });
  renderSummary(summary, { result, severity, showChanges: Boolean(result.baseline_scan),
    onSeverity: (s) => { state.severity = s; if (state.tab === "coverage") state.tab = "all"; saveView(); render(); },
    onTab: setTab });
  const tabs = h("nav", { className: "tabs", role: "tablist" });
  renderTabs(tabs, { tab, counts: tabCounts(result.findings), visible, onTab: setTab });
  if (tab === "coverage") {
    const pane = h("section", { className: "coverage-pane panel" });
    renderCoverage(pane, { result, names: state.names });
    return [summary, tabs, pane];
  }

  const list = groups(result.findings, tab, severity);
  if (tab === "all" && !severity && !list.length) {
    return [summary, tabs, h("section", { className: "center panel tint-green" },
      h("p", { className: "big", textContent: "✓ 이번 검사에서 찾은 위험 후보가 없어요" }),
      h("button", { type: "button", className: "link", textContent: "검사하지 못한 영역은 검사 범위 탭에서 확인하세요 →",
        onclick: () => setTab("coverage") }))];
  }
  parts.list = h("aside", { className: "list-pane panel", ariaLabel: "위험 목록" });
  parts.detail = h("section", { className: "detail-pane panel", ariaLabel: "상세" });
  renderPanes(list, tab);
  return [summary, tabs, h("div", { className: "panes" }, parts.list, parts.detail)];
}

// state.selected는 사용자가 고른 묶음. 지금 목록에 없으면 첫 묶음을 보여 주되 고른 것은 기억해 둔다 (탭을 돌아오면 다시 보임)
function renderPanes(list, tab) {
  const shown = keepSelection(list, state.selected);
  if (!list.length) {
    parts.list.replaceChildren(h("p", { className: "empty muted", textContent: EMPTY[tab] }));
    parts.detail.replaceChildren();
    return;
  }
  renderList(parts.list, { list, tab, selected: shown, firstScan: !state.result.baseline_scan,
    onSelect: (ruleId) => { state.selected = ruleId; renderPanes(list, tab); } });
  renderDetail(parts.detail, { group: list.find((g) => g.rule_id === shown), tab, firstScan: !state.result.baseline_scan,
    names: state.names, repo: repo(), result: state.result });
}

function setTab(tab) {
  state.tab = tab;
  saveView();
  render();
}

// ---------- 동작 ----------

async function guard(action) {
  try {
    await action();
  } catch (err) {
    if (err.offline) return goOffline();
    state.failed = err.message;
    render();
  }
}

async function loadResult() {
  const id = state.repoId;
  const last = repo()?.last_scan;
  const result = last ? await api(`/api/scans/${last.id}`) : null;
  if (state.repoId === id) state.result = result;   // 기다리는 사이 다른 프로젝트를 골랐으면 버린다
}

async function selectRepo(id) {
  Object.assign(state, { repoId: id, failed: null, selected: null });
  await loadResult();
  render();
}

function addRepo() {
  const dialog = h("dialog", { className: "dialog" });
  const body = h("div");
  const close = h("button", { type: "button", className: "dialog-close", ariaLabel: "닫기", textContent: "✕",
    onclick: () => dialog.close() });
  dialog.append(close, body);
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  renderStart(body, { api, onStarted: (data) => { dialog.close(); guard(() => started(data)); } });
  dialog.showModal();
}

async function started({ repo: added, scan_id }) {
  state.repos = await api("/api/repos");
  Object.assign(state, { repoId: added.id, result: null, failed: null, selected: null });
  watch({ scan_id, repo_id: added.id, status: "queued", stage: null });
  render();
}

async function rescan() {
  const repoId = state.repoId;   // 기다리는 사이 프로젝트를 바꿔도 요청한 프로젝트에 붙인다
  const { scan_id } = await api("/api/scans", { method: "POST", body: { repo_id: repoId } });
  if (state.repoId === repoId) state.failed = null;
  watch({ scan_id, repo_id: repoId, status: "queued", stage: null });
  render();
}

// 진행은 상단 바만 다시 그리고, 끝나면 조용히 전체를 다시 그린다 (토스트·알림 없음, 선택 유지)
function watch(job) {
  sources[job.repo_id]?.close();
  state.jobs[job.repo_id] = job;
  const source = sources[job.repo_id] = new EventSource(`/api/scans/${job.scan_id}/events`);
  const stop = () => { source.close(); if (sources[job.repo_id] === source) delete sources[job.repo_id]; };
  source.addEventListener("progress", ({ data }) => {
    state.jobs[job.repo_id] = JSON.parse(data);
    if (job.repo_id === state.repoId) state.result ? renderTop() : render();
  });
  const finish = (failed) => ({ data }) => guard(async () => {
    stop();
    delete state.jobs[job.repo_id];
    state.repos = await api("/api/repos");
    const mine = job.repo_id === state.repoId;   // 목록을 받는 사이 프로젝트를 바꿨을 수 있어 받은 뒤에 본다
    if (mine && failed) state.failed = JSON.parse(data).error || "알 수 없는 오류";
    if (mine && !failed) { state.failed = null; await loadResult(); }
    render();
  });
  source.addEventListener("done", finish(false));
  source.addEventListener("failed", finish(true));
  // 연결이 끊기면 서버가 살아 있는지 보고 같은 검사를 다시 지켜본다 (이미 끝났으면 서버가 done을 바로 보냄)
  source.onerror = () => { stop(); setTimeout(() => resume(job), 2000); };
}

async function resume(job) {
  try {
    await api("/api/state");   // 서버가 살아 있고 이 브라우저를 아직 알아보는지 (티켓이 바뀌었으면 그 문장을 보인다)
  } catch (err) {
    if (err.offline) return goOffline();
    delete state.jobs[job.repo_id];
    state.failed = err.message;
    return render();
  }
  if (state.jobs[job.repo_id]?.scan_id === job.scan_id && !sources[job.repo_id]) watch(state.jobs[job.repo_id]);
}

async function checkServer() {
  try {
    await fetch("/healthz");
    await boot();
  } catch {
    goOffline();
  }
}

function goOffline() {
  state.offline = true;
  for (const repoId of Object.keys(sources)) { sources[repoId].close(); delete sources[repoId]; }
  state.jobs = {};
  render();
  setTimeout(checkServer, 10000);
}

async function boot() {
  try {
    const info = await api("/api/state");
    state.offline = false;
    state.latestScan = info.latest_scan;
    api("/api/settings").then((settings) => window.setTheme(settings.theme), () => {});
    const names = await api("/api/catalog").catch(() => null);
    if (names) state.names = { ws: Object.fromEntries(names.ws.map((w) => [w.code, w.name_ko])),
      owasp: Object.fromEntries(names.owasp.map((o) => [o.code, o.name])) };
    state.repos = info.repos ? await api("/api/repos") : [];
    state.repoId = info.running?.repo_id ?? info.last_repo ?? state.repos[0]?.id ?? null;
    await loadResult();
    if (info.running) watch(info.running);
    render();
  } catch (err) {
    if (err.offline) return goOffline();
    root.replaceChildren(h("section", { className: "center panel" }, h("p", { className: "status-bad", textContent: err.message })));
  }
}

// 다른 곳(커밋 자동 검사)에서 시작·끝난 검사를 조용히 반영한다. 토스트·알림 없음 (PRD P6)
async function poll() {
  if (state.offline) return;
  try {
    const info = await api("/api/state");
    if (info.running && !state.jobs[info.running.repo_id]) watch(info.running);
    if (info.latest_scan === state.latestScan) return;
    state.latestScan = info.latest_scan;
    state.repos = await api("/api/repos");
    await loadResult();
    render();
  } catch (err) {
    if (err.offline) goOffline();
  }
}

setInterval(poll, 5000);
setInterval(() => state.result && !jobHere() && renderTop(), 60000);   // "n분 전" 갱신
document.addEventListener("click", (event) => {   // 펼친 메뉴(프로젝트·보고서) 바깥을 누르면 닫는다
  for (const menu of document.querySelectorAll("details.popover[open]")) if (!menu.contains(event.target)) menu.open = false;
});
boot();
