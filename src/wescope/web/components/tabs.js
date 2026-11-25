// 보기 탭 (DASHBOARD.md §3-4). shortcut: 검사 범위 탭은 F3(coverage.js)에서 붙인다.
import { h } from "../dom.js";

const LABELS = { all: "전체", new: "NEW", fixed: "FIXED", ai: "AI", dismissed: "오탐 표시" };

export function renderTabs(el, { tab, counts, visible, onTab }) {
  el.replaceChildren(...visible.map((key) => {
    const button = h("button", { type: "button", role: "tab", className: "tab", ariaSelected: String(key === tab) },
      LABELS[key], h("span", { className: "tab-count", textContent: String(counts[key]) }));
    button.addEventListener("click", () => onTab(key));
    return button;
  }));
}
