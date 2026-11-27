// 오른쪽 상세: 머리(심각도·기술 이름·한 줄 설명) + 탭(수정안·설명·위치·판정 정보) + 버튼 (DASHBOARD.md §3-6·§6)
import { h, sevClass } from "../dom.js";
import { CHANGE_KO } from "../wording.js";
import { tags, TAG_CLASS, VERIFY, groupFix } from "./list.js";
import { buildPrompt, place } from "./prompt.js";

const DETAIL_TABS = ["fix", "why", "where", "meta"];
const CONFIDENCE_KO = {
  flow: "흐름을 직접 확인했어요",
  absence: "보호 코드가 없어 보인다는 추정이에요",
  ai_confirmed: "ChatGPT가 주변 코드로 확인했어요",
  ai: "ChatGPT가 찾았어요",
};
const TRIAGE_KO = {
  confirmed: "ChatGPT가 주변 코드로 확인했어요",
  protected: "ChatGPT가 보호 코드를 찾았어요",
  unclear: "ChatGPT도 판단하지 못했어요",
};
let current = "fix";   // 고른 상세 탭은 다른 묶음을 골라도 유지

const section = (title, ...body) => h("section", { className: "detail-section" }, h("h3", { textContent: title }), ...body);
const para = (text) => h("p", { className: "prose", textContent: text });
const code = (text) => h("pre", { className: "code" }, h("code", { textContent: text }));
const items = (list) => h("ul", { className: "prose-list" },
  ...list.map((t) => h("li", { textContent: typeof t === "string" ? t : JSON.stringify(t) })));

export const diffClass = (line) =>
  /^(\+\+\+|---) /.test(line) ? "diff-file" : line.startsWith("@@") ? "diff-hunk"
    : line[0] === "+" ? "diff-add" : line[0] === "-" ? "diff-remove" : "";

function diffView(diff) {
  return h("pre", { className: "code diff" },
    ...diff.replace(/\n$/, "").split("\n").map((line) => h("span", { className: diffClass(line), textContent: `${line}\n` })));
}

function basicFix(f) {
  return [
    section("기본 수정 방법", para(f.fix_ko), f.fix_example && code(f.fix_example.trimEnd())),
    f.avoid_ko && h("p", { className: "notice-amber", textContent: `하지 말 것: ${f.avoid_ko}` }),
  ];
}

// ChatGPT 수정안이 있으면 검증 상태 → 요약 → diff → 동작 변화 → 코드 밖에서 할 일 → 새 의존성 → 확인 방법 (§6-1)
function fixTab(f, fix) {
  if (!fix) return basicFix(f);
  const [, label, tone] = VERIFY[fix.verification] ?? VERIFY.failed;
  const reasons = fix.verification === "failed" ? fix.checks?.reasons ?? [] : [];
  return [
    h("p", { className: `verify ${tone}`, textContent: label }),
    reasons.length && items(reasons),
    section("ChatGPT 수정안", para(fix.summary_ko), diffView(fix.diff)),
    fix.behavior_change_ko && section("바뀌는 동작", para(fix.behavior_change_ko)),
    fix.follow_ups?.length && section("코드 밖에서 할 일", items(fix.follow_ups)),
    fix.new_dependencies?.length && section("새 의존성", items(fix.new_dependencies)),
    fix.test_hint_ko && section("확인 방법", para(fix.test_hint_ko)),
    ...(fix.verification === "failed" ? basicFix(f) : []),
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
  const t = f.triage;
  const ev = t?.evidence;
  const rows = [
    ["WS 영역", `${f.category} ${names.ws[f.category] ?? ""}`],
    ["OWASP", f.owasp ? `${f.owasp} ${names.owasp[f.owasp] ?? ""}` : "OWASP Top 10 범위 밖"],
    f.owasp_ai.length && ["LLM·에이전트", f.owasp_ai.join(", ")],
    ["CWE", f.cwe || "없음"],
    ["신뢰도", `${f.confidence} — ${CONFIDENCE_KO[f.confidence_source] ?? ""}`],
    f.source === "ai" && ["AI 발견", "ChatGPT가 찾은 위험 후보예요. 정적 분석으로는 확인하지 못했어요."],
    f.extra?.attack_scenario_ko && ["공격 시나리오", f.extra.attack_scenario_ko],
    f.extra?.ai_also_ko && ["ChatGPT", f.extra.ai_also_ko],
    t && ["ChatGPT 확인", [TRIAGE_KO[t.verdict], t.reason_ko].filter(Boolean).join(" — ")],
    t?.impact_ko && ["영향", t.impact_ko],
    ev && ["근거 위치", `${ev.file}:${ev.line_start}${ev.line_end > ev.line_start ? `-${ev.line_end}` : ""}`],
    t?.note_ko && ["참고", t.note_ko],
    f.introduced_in && ["처음 발견", f.introduced_in.slice(0, 7)],
    ["규칙 ID", f.rule_id],
  ].filter(Boolean);
  return [h("dl", { className: "meta" }, ...rows.flatMap(([k, v]) => [h("dt", { textContent: k }), h("dd", { textContent: v })]))];
}

function copyButton(label, getText, className = "btn") {
  const button = h("button", { type: "button", className, textContent: label });
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

// 오탐 표시는 다음 검사부터 결과(status·요약)에 반영된다. 그 전에는 목록을 옮기지 않고 표시했다는 사실만 보인다 (§8-6 결정)
function ignoreNotice(group, tab, marked, ignores) {
  if (tab === "dismissed" && !marked.length) {
    return h("p", { className: "notice-blue", textContent: "오탐 표시를 해제했어요. 다음 검사부터 다시 목록에 보여요." });
  }
  if (!marked.length) return null;
  const { reason, created_at } = ignores[marked[0].fingerprint];
  const count = marked.length < group.findings.length ? ` (${group.findings.length}곳 중 ${marked.length}곳)` : "";
  const later = tab === "dismissed" ? "" : " 다음 검사부터 목록·요약에서 빠져요.";
  return h("p", { className: "notice-blue" },
    `오탐으로 표시했어요${count} · ${new Date(created_at).toLocaleString("ko-KR")}.${later}`,
    h("br"), `이유: ${reason || "적지 않음"}`);
}

function ignoreForm(unmarked, suggested, onSubmit, onCancel) {
  const reason = h("textarea", { rows: 2, maxLength: 500, placeholder: "예: 상위 미들웨어에서 관리자 확인을 해요",
    value: suggested?.reason_ko ?? "" });
  const picks = unmarked.length > 1 ? unmarked.map((f) => {
    const box = h("input", { type: "checkbox", checked: true });
    box.dataset.fingerprint = f.fingerprint;
    return h("label", { className: "check" }, box, h("span", { className: "mono", textContent: place(f) }));
  }) : [];
  const submit = h("button", { type: "submit", className: "btn btn-primary", textContent: "오탐으로 표시" });
  const form = h("form", { className: "ignore-form" },
    h("label", { className: "field" }, h("span", { textContent: "오탐인 이유 (선택)" }), reason),
    picks.length > 0 && h("fieldset", { className: "picks" }, h("legend", { textContent: "표시할 위치" }), ...picks),
    h("div", { className: "form-actions" }, submit,
      h("button", { type: "button", className: "btn btn-ghost", textContent: "취소", onclick: onCancel })));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const chosen = picks.length ? picks.map((p) => p.firstChild).filter((b) => b.checked).map((b) => b.dataset.fingerprint)
      : [unmarked[0].fingerprint];
    if (chosen.length) onSubmit(chosen, reason.value.trim(), submit);
  });
  return form;
}

// 버튼 줄. 요청이 실패하면 서버의 detail을 버튼 바로 아래에 보인다. 성공하면 app.js가 상세를 다시 그린다
function actionBar({ group, tab, repo, result, ignores, busy, actions }) {
  const fix = groupFix(group);
  const marked = group.findings.filter((f) => ignores[f.fingerprint]);
  const unmarked = group.findings.filter((f) => !ignores[f.fingerprint]);
  const suggested = group.findings.find((f) => f.triage?.suggested === "dismiss")?.triage;
  const error = h("p", { className: "error", hidden: true });
  const slot = h("div");
  const run = async (button, work) => {
    button.disabled = true;
    error.hidden = true;
    try {
      await work();
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
      button.disabled = false;
    }
  };
  const button = (label, className, work, disabled = false) => {
    const b = h("button", { type: "button", className, textContent: label, disabled });
    b.addEventListener("click", () => work(b));
    return b;
  };
  const open = tab !== "dismissed";
  const row = h("div", { className: "detail-actions" },
    open && copyButton("수정 요청 프롬프트 복사", () => buildPrompt({ repo, result, group }), "btn btn-primary"),
    open && fix?.diff && copyButton("diff 복사", () => fix.diff),
    open && unmarked.length > 0 && button(fix ? "다른 수정안" : "수정안 만들기", "btn",
      (b) => run(b, () => actions.makeFix(group.rule_id, Boolean(fix))), busy),
    open && unmarked.length > 0 && button("오탐이에요", suggested ? "btn btn-suggest" : "btn btn-ghost", (b) => {
      b.hidden = true;
      slot.replaceChildren(ignoreForm(unmarked, suggested,
        (fingerprints, reason, submit) => run(submit, () => actions.ignore(fingerprints, reason)),
        () => { slot.replaceChildren(); b.hidden = false; }));
      slot.scrollIntoView({ block: "nearest" });   // 상세 맨 아래에 펼쳐져 화면 밖에 생기므로
    }),
    marked.length > 0 && button("오탐 해제", "btn btn-ghost", (b) => run(b, () => actions.unignore(marked.map((f) => f.fingerprint)))));
  return [ignoreNotice(group, tab, marked, ignores), row, slot, error];
}

export function renderDetail(el, { group, tab, firstScan, names, repo, result, ignores = {}, busy = false, actions }) {
  const f = group.findings[0];
  const fix = groupFix(group);
  const suspect = group.findings.some((x) => x.triage?.instruction_suspect || x.fix?.instruction_suspect);
  const suggested = tab !== "dismissed" && group.findings.some((x) => x.triage?.suggested === "dismiss");
  const head = h("header", { className: "detail-head" },
    h("p", { className: "detail-tags" },
      h("span", { className: sevClass(group.severity), textContent: group.severity }),
      h("span", { className: "spacer" }),
      ...tags(group, tab, firstScan).map((t) => h("span", { className: `tag ${TAG_CLASS[t] || ""}`, textContent: t })),
      group.findings.length > 1 && h("span", { className: "row-count", textContent: `${group.findings.length}곳` })),
    h("h2", { className: "detail-title", textContent: f.tech_name_ko }),
    h("p", { className: "muted", textContent: f.title_ko }),
    suspect && h("p", { className: "notice-amber", textContent: "주의: 지시문 같은 텍스트가 있는 파일이에요" }),
    suggested && h("p", { className: "notice-blue",
      textContent: "ChatGPT가 보호 코드를 찾았어요. 판정 정보 탭에서 근거를 확인하고, 맞으면 [오탐이에요]로 표시하세요." }));

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
    body.replaceChildren(...{ fix: () => fixTab(f, fix), why: () => whyTab(f), where: () => whereTab(group, firstScan),
      meta: () => metaTab(f, names) }[key]().filter(Boolean));
  };
  bar.append(...DETAIL_TABS.map((key) => {
    const b = h("button", { type: "button", role: "tab", className: "tab", textContent: labels[key] });
    b.dataset.key = key;
    b.addEventListener("click", () => show(key));
    return b;
  }));
  show(current);
  el.replaceChildren(head, bar, body,
    ...actionBar({ group, tab, repo, result, ignores, busy, actions }).filter(Boolean));
}
