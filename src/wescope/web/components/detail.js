// 오른쪽 상세: 머리(심각도·기술 이름·한 줄 설명) + 탭(수정안·설명·위치·판정 정보) + 버튼 (DASHBOARD.md §3-6)
import { h, sevClass } from "../dom.js";
import { CHANGE_KO } from "../wording.js";
import { tags, TAG_CLASS } from "./list.js";
import { buildPrompt, place } from "./prompt.js";

const DETAIL_TABS = ["fix", "why", "where", "meta"];
const CONFIDENCE_KO = {
  flow: "흐름을 직접 확인했어요",
  absence: "보호 코드가 없어 보인다는 추정이에요",
  ai_confirmed: "ChatGPT가 주변 코드로 확인했어요",
  ai: "ChatGPT가 찾았어요",
};
let current = "fix";   // 고른 상세 탭은 다른 묶음을 골라도 유지

const section = (title, ...body) => h("section", { className: "detail-section" }, h("h3", { textContent: title }), ...body);
const para = (text) => h("p", { className: "prose", textContent: text });
const code = (text) => h("pre", { className: "code" }, h("code", { textContent: text }));

function fixTab(f) {
  // shortcut: ChatGPT 수정안(fix)은 B8에서 검증 상태·diff 보기와 함께 붙인다. 지금은 규칙의 기본 수정 방법만
  return [
    section("기본 수정 방법", para(f.fix_ko), f.fix_example && code(f.fix_example.trimEnd())),
    f.avoid_ko && h("p", { className: "notice-amber", textContent: `하지 말 것: ${f.avoid_ko}` }),
  ];
}

function whyTab(f) {
  return [section("무슨 일이 생길 수 있나요", para(f.why_ko)),
    f.limitations_ko && section("이 발견이 증명하지 않는 것", para(f.limitations_ko))];
}

function whereTab(group, firstScan) {
  return group.findings.map((f) => h("div", { className: "place" },
    h("p", { className: "place-head" },
      h("span", { className: "mono", textContent: place(f) }),
      f.severity !== group.severity && h("span", { className: sevClass(f.severity), textContent: f.severity }),
      !firstScan && f.change === "new" && h("span", { className: "tag tag-new", textContent: "NEW" })),
    f.location.line > 0 ? code(f.evidence) : h("p", { className: "muted", textContent: "파일 전체" }),
    f.change === "unknown" && h("p", { className: "muted", textContent: CHANGE_KO.unknown })));
}

function metaTab(f, names) {
  const rows = [
    ["WS 영역", `${f.category} ${names.ws[f.category] ?? ""}`],
    ["OWASP", f.owasp ? `${f.owasp} ${names.owasp[f.owasp] ?? ""}` : "OWASP Top 10 범위 밖"],
    f.owasp_ai.length && ["LLM·에이전트", f.owasp_ai.join(", ")],
    ["CWE", f.cwe || "없음"],
    ["신뢰도", `${f.confidence} — ${CONFIDENCE_KO[f.confidence_source] ?? ""}`],
    f.introduced_in && ["처음 발견", f.introduced_in.slice(0, 7)],
    ["규칙 ID", f.rule_id],
  ].filter(Boolean);
  return [h("dl", { className: "meta" }, ...rows.flatMap(([k, v]) => [h("dt", { textContent: k }), h("dd", { textContent: v })]))];
}

function copyButton(getText) {
  const label = "수정 요청 프롬프트 복사";
  const button = h("button", { type: "button", className: "btn btn-primary", textContent: label });
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(getText());
      button.textContent = "복사했어요 ✓";
    } catch {
      button.textContent = "복사하지 못했어요";
    }
    setTimeout(() => { button.textContent = label; }, 2000);
  });
  return button;
}

export function renderDetail(el, { group, tab, firstScan, names, repo, result }) {
  const f = group.findings[0];
  const head = h("header", { className: "detail-head" },
    h("p", { className: "detail-tags" },
      h("span", { className: sevClass(group.severity), textContent: group.severity }),
      h("span", { className: "spacer" }),
      ...tags(group, tab, firstScan).map((t) => h("span", { className: `tag ${TAG_CLASS[t] || ""}`, textContent: t })),
      group.findings.length > 1 && h("span", { className: "row-count", textContent: `${group.findings.length}곳` })),
    h("h2", { className: "detail-title", textContent: f.tech_name_ko }),
    h("p", { className: "muted", textContent: f.title_ko }));

  if (tab === "fixed") {
    el.replaceChildren(head, h("p", { className: "notice-green", textContent: "직전 검사에 있었고 이번 검사에서 사라졌어요" }),
      ...whereTab(group, true));
    return;
  }

  const labels = { fix: "수정안", why: "설명", where: `위치 ${group.findings.length}`, meta: "판정 정보" };
  const body = h("div", { className: "detail-body", role: "tabpanel" });
  const bar = h("nav", { className: "detail-tabs", role: "tablist" });
  const show = (key) => {
    current = key;
    for (const b of bar.children) b.ariaSelected = String(b.dataset.key === key);
    body.replaceChildren(...{ fix: () => fixTab(f), why: () => whyTab(f), where: () => whereTab(group, firstScan),
      meta: () => metaTab(f, names) }[key]().filter(Boolean));
  };
  bar.append(...DETAIL_TABS.map((key) => {
    const b = h("button", { type: "button", role: "tab", className: "tab", textContent: labels[key] });
    b.dataset.key = key;
    b.addEventListener("click", () => show(key));
    return b;
  }));
  show(current);
  // 오탐 탭은 [오탐 되돌리기](B7)만 둘 자리라 지금은 버튼 없음
  const actions = tab === "dismissed" ? null
    : h("div", { className: "detail-actions" }, copyButton(() => buildPrompt({ repo, result, group })));
  el.replaceChildren(head, bar, body, actions ?? "");
}
