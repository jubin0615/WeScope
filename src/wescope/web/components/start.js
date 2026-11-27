// 시작 화면: 폴더 경로 / GitHub 주소 중 하나를 받아 POST /api/repos (DASHBOARD.md §3-1).
import { h } from "../dom.js";
import { sendTable } from "./settings.js";

// 입력 칸 값 → 요청 본문. 둘 중 하나만 채워야 한다. 형식 검사(폴더 존재·GitHub 주소)는 서버가 한다.
export function target(path, github, branch) {
  path = path.trim(); github = github.trim(); branch = branch.trim();
  if (path && github) return { error: "폴더 경로와 GitHub 주소 중 하나만 입력하세요" };
  if (path) return { body: { path } };
  if (github) return { body: branch ? { github, branch } : { github } };
  return { error: null };   // 아무것도 안 채움: 버튼만 꺼 두고 문장은 띄우지 않는다
}

function field(label, placeholder) {
  const input = h("input", { type: "text", placeholder, spellcheck: false, autocomplete: "off" });
  return { wrap: h("label", { className: "field" }, h("span", { textContent: label }), input), input };
}

export function renderStart(root, { api, onStarted }) {
  const path = field("프로젝트 폴더 경로", "C:\\Users\\me\\projects\\my-app");
  const github = field("GitHub 주소", "https://github.com/owner/repo");
  const branch = field("브랜치 (선택)", "main");
  const error = h("p", { className: "error", hidden: true });
  const submit = h("button", { type: "submit", className: "btn btn-primary", textContent: "검사 시작", disabled: true });

  const form = h("form", { className: "start panel", noValidate: true },
    h("h1", { className: "brand", textContent: "We-Scope" }),
    h("p", { className: "start-lead", textContent: "내 웹앱 코드에서 보안 위험 후보를 찾아 한국어로 설명해요" }),
    path.wrap,
    h("p", { className: "start-or", textContent: "또는" }),
    github.wrap, branch.wrap,
    error,
    h("div", { className: "start-actions" }, submit),
    h("section", { className: "notice" },
      h("h2", { textContent: "어디로 무엇을 보내나요" }),
      h("ul", {},
        h("li", { className: "yes", textContent: "검사는 이 PC 안에서만 해요. 코드를 밖으로 보내지 않아요." }),
        h("li", { className: "yes", textContent: "원본 폴더는 읽기만 하고 고치지 않아요." }),
        h("li", { textContent: "GitHub 주소는 이 PC로 내려받은 뒤 검사해요." }),
        h("li", { textContent: "ChatGPT 분석은 나중에 직접 켰을 때만 써요. 보내는 것은 설정 창에서 확인할 수 있어요." })),
      h("details", { className: "send-details" }, h("summary", { textContent: "자세히" }), sendTable())));

  let busy = false;   // 요청 중에는 입력을 고쳐도 버튼을 다시 켜지 않는다 (두 번 등록 방지)
  const show = (message) => { error.textContent = message || ""; error.hidden = !message; };
  const update = () => {
    branch.wrap.hidden = !github.input.value.trim();
    const { body, error: problem } = target(path.input.value, github.input.value, branch.input.value);
    submit.disabled = busy || !body;
    show(problem);
  };
  form.addEventListener("input", update);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const { body } = target(path.input.value, github.input.value, branch.input.value);
    if (busy || !body) return;
    busy = true;
    submit.disabled = true;
    submit.textContent = "시작하는 중…";
    try {
      onStarted(await api("/api/repos", { method: "POST", body }));
    } catch (err) {
      busy = false;
      submit.textContent = "검사 시작";
      update();
      show(err.message);
    }
  });

  update();
  root.replaceChildren(form);
  path.input.focus();
}
