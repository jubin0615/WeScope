// 검사 범위 탭: We-Scope Top 10 · OWASP Top 10:2025 · ChatGPT 검토 범위 · 검사 도구 상태 (DASHBOARD.md §3-7)
import { h } from "../dom.js";
import { STATE_KO, ANALYZER_STATUS_KO, OWASP_SCOPE_TITLE, NOT_A_GUARANTEE, LIMITS } from "../wording.js";

const ICON = {
  vulnerable: ["⚠", "icon-bad"], clean: ["✓", "icon-good"], partial: ["◐", "icon-warn"],
  skipped: ["✕", "icon-muted"], not_applicable: ["–", "icon-muted"], manual: ["?", "icon-info"],
};

function table(rows, names, withNotes) {
  const head = ["영역", "상태", "발견", withNotes && "사유"].filter(Boolean);
  return h("table", { className: "coverage" },
    h("thead", {}, h("tr", {}, ...head.map((t) => h("th", { textContent: t })))),
    h("tbody", {}, ...rows.map((r) => {
      const [icon, tone] = ICON[r.state] ?? ["", ""];
      return h("tr", {},
        h("td", {}, h("span", { className: "mono", textContent: r.code }), ` ${names[r.code] ?? ""}`),
        h("td", {}, h("span", { className: `state-icon ${tone}`, ariaHidden: "true", textContent: icon }), STATE_KO[r.state] ?? r.state),
        h("td", { className: "num", textContent: r.findings ? String(r.findings) : "–" }),
        withNotes && h("td", { className: "muted", textContent: r.notes.join("; ") }));
    })));
}

export function renderCoverage(el, { result, names }) {
  const ai = result.ai_coverage.length
    ? [table(result.ai_coverage, {}, true), h("p", { className: "muted", textContent: "AI가 살펴본 범위예요. 놓친 것이 있을 수 있어요." })]
    : [h("p", { className: "muted", textContent: "ChatGPT 분석을 하지 않았어요. 업무 로직 인가·결제·파일 간 흐름은 직접 확인이 필요해요." })];
  const langs = Object.keys(result.profile.languages ?? {}).join(", ") || "없음";
  const frameworks = (result.profile.frameworks ?? []).join(", ") || "없음";
  el.replaceChildren(
    h("p", { className: "notice-blue", textContent: NOT_A_GUARANTEE }),
    h("h3", { textContent: "We-Scope Top 10" }), table(result.coverage, names.ws, true),
    h("h3", { textContent: OWASP_SCOPE_TITLE }), table(result.owasp_coverage, names.owasp, false),
    h("h3", { textContent: "ChatGPT 검토 범위" }), ...ai,
    h("details", { className: "tools" },
      h("summary", { textContent: "검사 도구 상태" }),
      h("ul", {}, ...result.analyzers.map((a) => h("li", {},
        h("span", { className: "mono", textContent: a.id }),
        ` ${ANALYZER_STATUS_KO[a.status] ?? a.status}${a.note ? ` — ${a.note}` : ""} (${a.elapsed.toFixed(1)}초)`))),
      h("p", { textContent: `언어: ${langs} · 프레임워크: ${frameworks}` }),
      result.summary.skipped_files > 0 && h("p", { textContent: `읽지 못한 파일 ${result.summary.skipped_files}개` }),
      h("ul", { className: "limits" }, ...LIMITS.map((t) => h("li", { textContent: t })))));
}
