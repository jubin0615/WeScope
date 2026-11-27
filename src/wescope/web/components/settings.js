// 설정 창: 이 프로젝트 · ChatGPT · 화면 · 데이터 (DASHBOARD.md §3-8). 가운데 <dialog>, 닫기는 ✕·Esc·바깥 누르기.
import { h } from "../dom.js";

const TABS = [["project", "이 프로젝트"], ["chatgpt", "ChatGPT"], ["screen", "화면"], ["data", "데이터"]];
const AI_LEVELS = [
  ["deep", "심층", "기본 + 정적 분석이 놓치는 업무 로직·결제·파일 간 흐름 검토"],
  ["basic", "기본", "의심 발견 확인 + 수정안 (CRITICAL·HIGH 자동, 나머지는 요청할 때)"],
  ["off", "끔", "정적 분석만 (규칙의 기본 설명·수정 예시)"],
];
const THEMES = [["system", "시스템 설정 따라가기"], ["light", "라이트"], ["dark", "다크"]];
// AI.md §8 — 바꿀 때는 그 표도 함께
const SENT = [
  ["발견이 있는 함수와 관련 정의", "저장소 전체"],
  ["보완 탐지 대상으로 고른 파일 (인증·결제·인가 등)", ".env·키·인증 파일"],
  ["파일 경로 목록, 프레임워크·라이브러리 이름과 버전", "탐지된 비밀값 (자리표시로 대체)"],
  ["정적 분석 결과 요약", "We-Scope 이력·다른 프로젝트 정보"],
];

// 한 줄에 패턴 하나. 빈 줄은 버린다 (서버도 같은 정리를 한다)
export const parseLines = (text) => text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);

export function sendTable() {
  return h("table", { className: "coverage send-table" },
    h("thead", {}, h("tr", {}, h("th", { textContent: "보냄 (AI 분석을 켰을 때)" }), h("th", { textContent: "보내지 않음" }))),
    h("tbody", {}, ...SENT.map(([yes, no]) => h("tr", {}, h("td", { textContent: yes }), h("td", { textContent: no })))));
}

// 요청 하나의 결과를 그 자리 바로 아래 문장으로 (오류는 서버 detail 그대로)
function feedback() {
  const p = h("p", { hidden: true });
  return Object.assign(p, {
    ok(text) { Object.assign(p, { className: "ok", textContent: text, hidden: false }); },
    fail(err) { Object.assign(p, { className: "error", textContent: err.message, hidden: false }); },
    clear() { p.hidden = true; },
  });
}

function radios(name, choices, value, onPick) {
  return h("div", { className: "radios" }, ...choices.map(([key, label, note]) => {
    const input = h("input", { type: "radio", name, value: key, checked: key === value });
    input.addEventListener("change", () => onPick(key, input));
    return h("label", { className: "check" }, input, h("span", {}, label, note && h("span", { className: "muted small", textContent: ` — ${note}` })));
  }));
}

function projectPanel({ api, repo, rules, onRepo }) {
  const excludes = h("textarea", { rows: 5, spellcheck: false, placeholder: "dist/\n*.min.js" });
  const disabled = new Set();
  const list = h("ul", { className: "rule-list" });
  const pick = h("select", { ariaLabel: "끌 규칙" });
  const note = feedback();
  const nameOf = (id) => rules[id] ?? id;
  const draw = () => {
    list.replaceChildren(...[...disabled].map((id) => h("li", {},
      h("span", { textContent: `${nameOf(id)} (${id})` }),
      h("button", { type: "button", className: "btn btn-small", textContent: "켜기", onclick: () => { disabled.delete(id); draw(); } }))));
    if (!disabled.size) list.append(h("li", { className: "muted", textContent: "꺼 둔 규칙이 없어요" }));
    pick.replaceChildren(...Object.keys(rules).filter((id) => !disabled.has(id))
      .map((id) => h("option", { value: id, textContent: `${nameOf(id)} (${id})` })));
  };
  const save = h("button", { type: "button", className: "btn btn-primary", textContent: "저장", disabled: true });
  api(`/api/repos/${repo.id}/settings`).then((s) => {
    excludes.value = s.excludes.join("\n");
    s.disabled_rules.forEach((id) => disabled.add(id));
    draw();
    save.disabled = false;
  }, (err) => note.fail(err));
  save.addEventListener("click", async () => {
    save.disabled = true;
    note.clear();
    try {
      const s = await api(`/api/repos/${repo.id}/settings`, { method: "POST",
        body: { excludes: parseLines(excludes.value), disabled_rules: [...disabled] } });
      excludes.value = s.excludes.join("\n");
      note.ok("저장했어요. 다음 검사부터 적용돼요.");
    } catch (err) {
      note.fail(err);
    }
    save.disabled = false;
  });

  const hookNote = feedback();
  const hook = repo.hook === null ? null : (() => {   // Git이 아닌 폴더·GitHub 주소는 커밋 자동 검사가 없다
    const box = h("input", { type: "checkbox", checked: repo.hook });
    box.addEventListener("change", async () => {
      box.disabled = true;
      hookNote.clear();
      try {
        const { hook: on } = await api(`/api/repos/${repo.id}/hook`, { method: "POST", body: { enabled: box.checked } });
        box.checked = on;
        onRepo({ ...repo, hook: on });
      } catch (err) {
        box.checked = !box.checked;
        hookNote.fail(err);
      }
      box.disabled = false;
    });
    return [h("h3", { textContent: "커밋 자동 검사" }),
      h("label", { className: "check" }, box, h("span", { textContent: "커밋할 때마다 자동으로 검사해요 (ChatGPT는 ChatGPT 탭 설정을 따라요)" })),
      hookNote];
  })();

  return h("section", {},
    h("h3", { textContent: "제외할 파일·폴더" }),
    h("label", { className: "field" }, h("span", { textContent: "한 줄에 패턴 하나" }), excludes),
    h("p", { className: "muted small", textContent: "폴더의 .wescopeignore도 함께 읽어요." }),
    h("h3", { textContent: "꺼 둔 규칙" }), list,
    h("div", { className: "inline" }, pick,
      h("button", { type: "button", className: "btn btn-small", textContent: "끄기",
        onclick: () => { if (pick.value) { disabled.add(pick.value); draw(); } } })),
    h("div", { className: "form-actions" }, save), note,
    ...(hook ?? []));
}

function chatgptPanel({ api, auth, settings, onAuth, onSettings, connectChatGPT }) {
  const panel = h("section");
  const note = feedback();
  const change = async (body, revert) => {
    note.clear();
    try {
      onSettings(await api("/api/settings", { method: "POST", body }));
    } catch (err) {
      revert();
      note.fail(err);
    }
  };
  const status = (current) => {
    const ready = current?.state === "ready";
    const button = ready
      ? h("button", { type: "button", className: "btn btn-small", textContent: "로그아웃" })
      : h("button", { type: "button", className: "btn btn-small", textContent: "ChatGPT 연결", onclick: connectChatGPT });
    if (ready) button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api("/api/auth/logout", { method: "POST" });
        line.replaceWith(status(await onAuth()));
      } catch (err) {
        button.disabled = false;
        note.fail(err);
      }
    });
    const line = h("div", { className: "inline" },
      h("span", { className: ready ? "chatgpt-on" : "muted", textContent: ready ? "◉ 연결했어요" : "○ 연결하지 않았어요" }),
      current?.message && h("span", { className: "muted small", textContent: current.message }),
      button);
    return line;
  };
  const hookBox = h("input", { type: "checkbox", checked: settings.ai_on_hook });
  hookBox.addEventListener("change", () => change({ ai_on_hook: hookBox.checked }, () => { hookBox.checked = !hookBox.checked; }));
  panel.append(
    h("h3", { textContent: "로그인" }), status(auth),
    h("h3", { textContent: "분석 수준" }),
    radios("ai_level", AI_LEVELS, settings.ai_level, (level) => {
      const before = settings.ai_level;
      change({ ai_level: level }, () => { panel.querySelector(`input[value="${before}"]`).checked = true; });
    }),
    h("label", { className: "check" }, hookBox,
      h("span", { textContent: "커밋 자동 검사에서도 ChatGPT 사용 (자리에 없는 동안 구독 사용량을 써요)" })),
    note,
    h("h3", { textContent: "어디로 무엇을 보내나요" }), sendTable(),
    h("p", { className: "muted small", textContent: "ChatGPT로는 위 표의 왼쪽만 보내요. 결과는 이 PC에만 저장해요." }));
  return panel;
}

function screenPanel({ api, settings, onSettings }) {
  const note = feedback();
  return h("section", {},
    h("h3", { textContent: "테마" }),
    radios("theme", THEMES, settings.theme, async (theme) => {
      window.setTheme(theme);   // 바로 적용, 저장은 전역 설정에
      note.clear();
      try { onSettings(await api("/api/settings", { method: "POST", body: { theme } })); } catch (err) { note.fail(err); }
    }),
    note);
}

function dataPanel({ api, repo, onRemoved, close }) {
  const note = feedback();
  const remove = h("button", { type: "button", className: "btn btn-danger", textContent: "연결 해제" });
  remove.addEventListener("click", async () => {
    remove.disabled = true;
    note.clear();
    try {
      await api(`/api/repos/${repo.id}`, { method: "DELETE" });
      close();
      onRemoved(repo.id);
    } catch (err) {
      remove.disabled = false;
      note.fail(err);   // 409: 검사가 끝난 뒤에 연결을 해제할 수 있어요
    }
  });
  return h("section", {},
    h("h3", { textContent: `${repo.name} 연결 해제` }),
    h("p", { textContent: "결과와 이력이 지워져요. 원본 폴더는 그대로예요." }),
    h("div", { className: "form-actions" }, remove), note);
}

export function openSettings(options) {
  const dialog = h("dialog", { className: "dialog settings" });
  const close = () => dialog.close();
  const panels = {
    project: projectPanel(options),
    chatgpt: chatgptPanel(options),
    screen: screenPanel(options),
    data: dataPanel({ ...options, close }),
  };
  const body = h("div", { className: "settings-body" });
  const bar = h("nav", { className: "detail-tabs", role: "tablist" });
  const show = (key) => {
    for (const b of bar.children) b.ariaSelected = String(b.dataset.key === key);
    body.replaceChildren(panels[key]);
  };
  bar.append(...TABS.map(([key, label]) => {
    const b = h("button", { type: "button", role: "tab", className: "tab", textContent: label, onclick: () => show(key) });
    b.dataset.key = key;
    return b;
  }));
  dialog.append(
    h("header", { className: "settings-head" }, h("h2", { textContent: "설정" }),
      h("button", { type: "button", className: "dialog-close", ariaLabel: "닫기", textContent: "✕", onclick: close })),
    bar, body);
  dialog.addEventListener("click", (event) => { if (event.target === dialog) close(); });   // 바깥(배경) 누르기
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  show(options.tab ?? "project");
  dialog.showModal();
}
