// 보기 탭 (DASHBOARD.md §3-4). 검사 범위 탭은 개수가 없다.
import { h } from "../dom.js";

const LABELS = { all: "전체", new: "NEW", fixed: "FIXED", ai: "AI", dismissed: "오탐 표시", coverage: "검사 범위" };

export function renderTabs(el, { tab, counts, visible, onTab }) {
  el.replaceChildren(...visible.map((key) => {
    const button = h("button", { type: "button", role: "tab", className: "tab", ariaSelected: String(key === tab) },
      LABELS[key], key in counts && h("span", { className: "tab-count", textContent: String(counts[key]) }));
    button.addEventListener("click", () => onTab(key));
    return button;
  }));
}
