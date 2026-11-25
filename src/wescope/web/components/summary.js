// 요약 줄: 심각도 개수(누르면 거름) · NEW/FIXED(누르면 탭 이동) · 위험 점수 (DASHBOARD.md §3-3)
import { h, SEVERITIES, sevClass } from "../dom.js";

export function renderSummary(el, { result, severity, showChanges, onSeverity, onTab }) {
  const { summary } = result;
  const sevButtons = SEVERITIES.map((s) => {
    const count = summary.severity[s];
    const button = h("button", { type: "button", className: "count", disabled: count === 0,
      ariaPressed: String(severity === s), title: count ? `${s}만 보기` : "" },
      h("span", { className: count ? sevClass(s) : "sev muted", textContent: s }),
      h("span", { className: "count-n", textContent: String(count) }));
    button.addEventListener("click", () => onSeverity(severity === s ? null : s));
    return button;
  });
  const change = (label, tab, count) => {
    const button = h("button", { type: "button", className: "count" },
      h("span", { className: `sev ${tab === "new" ? "tag-new" : "muted"}`, textContent: label }),
      h("span", { className: "count-n", textContent: String(count) }));
    button.addEventListener("click", () => onTab(tab));
    return button;
  };
  el.replaceChildren(...[
    h("div", { className: "counts" }, ...sevButtons),
    showChanges && h("div", { className: "counts" }, change("NEW", "new", summary.new), change("FIXED", "fixed", summary.fixed)),
    h("span", { className: "spacer" }),
    h("span", { className: "risk", title: "심각도·신뢰도로 계산한 참고 숫자예요. 안전 점수가 아니에요." },
      `위험 점수 ${summary.risk_score} ⓘ`)].filter(Boolean));
}
