// 왼쪽 위험 목록: 탭·심각도로 거르고 rule_id로 묶는다 (DASHBOARD.md §3-4·§3-5).
import { h, SEVERITIES, sevClass } from "../dom.js";

const open = (f) => f.status === "open" && f.change !== "fixed";
const TAB_FILTERS = {
  all: open,
  new: (f) => open(f) && f.change === "new",
  fixed: (f) => f.change === "fixed",
  ai: (f) => open(f) && (f.source === "ai" || f.confidence_source === "ai_confirmed"),
  dismissed: (f) => f.status === "dismissed",
};
export const TABS = Object.keys(TAB_FILTERS);

// 묶음 순서 = 엔진이 준 findings 순서(심각도 → 파일 → 줄)에서 그 rule_id가 처음 나온 자리.
export function groups(findings, tab, severity = null) {
  const byRule = new Map();
  for (const f of findings) {
    if (!TAB_FILTERS[tab](f) || (severity && f.severity !== severity)) continue;
    if (!byRule.has(f.rule_id)) byRule.set(f.rule_id, { rule_id: f.rule_id, findings: [] });
    byRule.get(f.rule_id).findings.push(f);
  }
  return [...byRule.values()].map((g) => ({
    ...g,
    severity: SEVERITIES.find((s) => g.findings.some((f) => f.severity === s)),
  }));
}

export const tabCounts = (findings) => Object.fromEntries(TABS.map((t) => [t, groups(findings, t).length]));

// 다시 그릴 때 보던 묶음을 유지하고, 없어졌으면 첫 묶음.
export const keepSelection = (list, ruleId) =>
  (list.some((g) => g.rule_id === ruleId) ? ruleId : list[0]?.rule_id ?? null);

export function where(f) {
  const { file, line, route } = f.location;
  return route || (line > 0 ? `${file}:${line}` : file);
}

export function tags(group, tab, firstScan) {
  if (tab === "fixed") return ["FIXED"];
  if (tab === "dismissed") return ["오탐"];
  const any = (test) => group.findings.some(test);
  return [
    !firstScan && any((f) => f.change === "new") && "NEW",   // 첫 검사는 모두 new라 붙이지 않는다
    any((f) => f.source === "ai") && "AI",
    any((f) => f.confidence_source === "ai_confirmed") && "AI 확인",
    any((f) => f.change === "unknown") && "확인 불가",
  ].filter(Boolean);
}

export const TAG_CLASS = { NEW: "tag-new", AI: "tag-ai", "AI 확인": "tag-ai" };
// 수정안 검증 상태 (DASHBOARD.md §6-1): [목록 행, 상세 머리, 색]
export const VERIFY = {
  verified: ["✓ 검증됨", "✓ 검증됨 — 적용·문법·재검사를 통과했어요", "icon-good"],
  partial: ["◐ 문법 확인", "◐ 문법 확인 — 적용·문법은 통과했지만 재검사로는 확인하지 못했어요", "icon-warn"],
  failed: ["✕ 검증 안 됨", "✕ 검증 안 됨 — 참고용이에요", "icon-muted"],
};
// 묶음의 수정안 = 대표 발견(서버가 고른 묶음의 첫 발견)에 붙은 fix
export const groupFix = (group) => group.findings.find((f) => f.fix)?.fix ?? null;
const shorten = (text, max = 44) => (text.length > max ? `…${text.slice(-(max - 1))}` : text);

export function renderList(el, { list, tab, selected, firstScan, onSelect }) {
  el.replaceChildren(...list.map((g) => {
    const first = g.findings[0];
    const more = g.findings.length - 1;
    const [verify, , tone] = VERIFY[groupFix(g)?.verification] ?? [];
    const row = h("button", { type: "button", className: "row", ariaPressed: String(g.rule_id === selected) },
      h("span", { className: sevClass(g.severity), textContent: g.severity }),
      h("span", { className: "row-title", textContent: first.tech_name_ko }),
      h("span", { className: "row-meta" },
        more > 0 && h("span", { className: "row-count", textContent: `${g.findings.length}곳` }),
        ...tags(g, tab, firstScan).map((t) => h("span", { className: `tag ${TAG_CLASS[t] || ""}`, textContent: t }))),
      h("span", { className: "row-where", title: where(first),
        textContent: shorten(where(first)) + (more > 0 ? ` 외 ${more}곳` : "") }),
      verify && h("span", { className: `row-verify ${tone}`, textContent: verify }));
    row.addEventListener("click", () => onSelect(g.rule_id));
    return row;
  }));
  el.querySelector('[aria-pressed="true"]')?.scrollIntoView({ block: "nearest" });
}
