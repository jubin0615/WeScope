// 상단 바: 로고 · 프로젝트 선택 · 상태 문장(또는 진행 표시) · [다시 스캔] (DASHBOARD.md §3-2·§4)
import { h, SEVERITIES, sevClass } from "../dom.js";

export const STAGES = [["collect", "파일 수집"], ["analyze", "정적 분석"], ["organize", "정리"], ["save", "저장"]];
const KIND_KO = { folder: "프로젝트 폴더", github: "GitHub 저장소" };
const OFFLINE = "서버와 연결이 끊겼어요. 터미널에서 wescope를 다시 실행하세요.";

export function relTime(iso, now = Date.now()) {
  const then = new Date(iso);
  const minutes = Math.floor((now - then) / 60000);
  if (minutes < 1) return "방금";
  if (minutes < 60) return `${minutes}분 전`;
  if (minutes < 24 * 60) return `${Math.floor(minutes / 60)}시간 전`;
  const pad = (n) => String(n).padStart(2, "0");
  return `${then.getMonth() + 1}월 ${then.getDate()}일 ${pad(then.getHours())}:${pad(then.getMinutes())}`;
}

// 마지막으로 받은 stage만 믿는다: 그 앞은 done, 그 단계는 current (SSE가 중간 단계를 건너뛸 수 있음)
export function renderProgress(job) {
  const at = STAGES.findIndex(([key]) => key === job.stage);
  const label = job.status === "queued" || at < 0 ? "대기 중…" : `${STAGES[at][1]} 중…`;
  return h("div", { className: "progress", role: "status" },
    h("span", { className: "progress-label" }, h("span", { className: "pulse" }), label),
    h("ol", {}, ...STAGES.map(([, name], i) =>
      h("li", { className: i < at ? "done" : i === at ? "current" : "", textContent: name }))));
}

function topSeverity(repo) {
  if (!repo.last_scan) return h("span", { className: "muted", textContent: "검사 전" });
  const counts = repo.last_scan.summary.severity;
  const top = SEVERITIES.find((s) => counts[s] > 0);
  return top ? h("span", { className: sevClass(top), textContent: top })
    : h("span", { className: "muted", textContent: "위험 후보 없음" });
}

function projectMenu({ repos, repo }, { selectRepo, addRepo }) {
  const menu = h("details", { className: "project-menu popover" },
    h("summary", { textContent: repo.name }),
    h("div", { className: "menu" },
      ...repos.map((r) => {
        const item = h("button", { type: "button", className: "menu-item", ariaCurrent: r.id === repo.id ? "true" : null },
          h("span", { className: "menu-name", textContent: r.name }),
          h("span", { className: "muted", textContent: KIND_KO[r.kind] }),
          topSeverity(r));
        item.addEventListener("click", () => { menu.open = false; selectRepo(r.id); });
        return item;
      }),
      h("button", { type: "button", className: "menu-item menu-add", textContent: "+ 프로젝트 추가",
        onclick: () => { menu.open = false; addRepo(); } })));
  return menu;
}

function statusLine({ repo, result, job, failed, offline }, { openCoverage }) {
  if (offline) return h("p", { className: "status status-bad", textContent: OFFLINE });
  if (job && result) return renderProgress(job);   // 첫 검사의 진행 표시는 가운데 판에
  if (failed) return h("p", { className: "status status-bad", textContent: `검사하지 못했어요: ${failed}` });
  if (!result) return h("p", { className: "status", textContent: job ? "첫 검사를 하고 있어요" : "아직 검사 결과가 없어요" });
  const parts = [`마지막 검사 ${relTime(result.scanned_at)}`];
  if (result.commit) parts.push(`커밋 ${result.commit.slice(0, 7)}${result.trigger === "hook" ? " (자동)" : ""}`);
  if (repo.kind === "github" && repo.branch) parts.push(repo.branch);
  const skipped = result.analyzers.some((a) => a.status === "skipped" || a.status === "failed");
  return h("p", { className: "status", title: new Date(result.scanned_at).toLocaleString("ko-KR") },
    parts.join(" · "),
    skipped && " · ",
    skipped && h("button", { type: "button", className: "link status-warn", textContent: "일부 검사 건너뜀", onclick: openCoverage }));
}

// ChatGPT 연결 상태 (DASHBOARD.md 8-8). 연결 전에는 누르면 새 탭에서 로그인. 로그아웃·분석 수준은 설정 창(F4)
function chatgpt(auth, { connectChatGPT }) {
  if (!auth) return null;
  if (auth.state === "ready") return h("span", { className: "chatgpt chatgpt-on", title: auth.message, textContent: "◉ ChatGPT" });
  return h("button", { type: "button", className: "link chatgpt", title: auth.message,
    textContent: "○ ChatGPT 연결 안 함", onclick: connectChatGPT });
}

export function renderTopbar(el, view, actions) {
  const rescan = h("button", { type: "button", className: "btn btn-primary",
    textContent: view.job ? "검사 중…" : "다시 스캔", disabled: Boolean(view.job || view.offline) });
  rescan.addEventListener("click", actions.rescan);
  el.replaceChildren(
    h("h1", { className: "brand", textContent: "We-Scope" }),
    projectMenu(view, actions),
    statusLine(view, actions),
    h("span", { className: "spacer" }),
    chatgpt(view.auth, actions),
    rescan);
}
