// 상태·API·화면 조립. 화면은 ScanResult JSON과 ARCHITECTURE.md §7-1 API만 쓴다.
import { renderStart } from "./components/start.js";

const root = document.getElementById("app");
const state = { repoId: null, scanId: null };

// 실패하면 서버의 {"detail"} 문장을 그대로 던진다. 서버에 닿지 못하면 연결 끊김 문장.
export async function api(path, { method = "GET", body } = {}) {
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error("서버와 연결이 끊겼어요. 터미널에서 wescope를 다시 실행하세요.");
  }
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.detail || `요청이 실패했어요 (${response.status})`);
  return data;
}

// shortcut: F1은 검사 시작까지만. 진행 표시·목록은 F2에서 이 자리를 채운다.
function renderPlaceholder(message) {
  const panel = document.createElement("section");
  panel.className = "placeholder panel";
  const title = Object.assign(document.createElement("h1"), { className: "brand", textContent: "We-Scope" });
  const text = Object.assign(document.createElement("p"), { className: "muted", textContent: message });
  panel.append(title, text);
  root.replaceChildren(panel);
}

function started({ repo, scan_id }) {
  state.repoId = repo.id;
  state.scanId = scan_id;
  renderPlaceholder(`${repo.name} 검사를 시작했어요. 진행 표시와 위험 목록은 다음 단계에서 이 자리에 보여요.`);
}

async function boot() {
  try {
    const info = await api("/api/state");
    if (info.repos === 0) return renderStart(root, { api, onStarted: started });
    state.repoId = info.running?.repo_id ?? info.last_repo;
    state.scanId = info.running?.scan_id ?? null;
    renderPlaceholder(info.running ? "검사하고 있어요." : "연결된 프로젝트가 있어요. 위험 목록은 다음 단계에서 보여요.");
  } catch (err) {
    renderPlaceholder(err.message);
  }
}

boot();
