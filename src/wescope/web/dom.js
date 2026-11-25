// 화면 조각을 만드는 작은 도우미. 사용자 문자열은 항상 textContent로만 넣는다 (innerHTML 금지).
export function h(tag, props = {}, ...children) {
  const el = Object.assign(document.createElement(tag), props);
  el.append(...children.filter((c) => c !== null && c !== undefined && c !== false));
  return el;
}

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const sevClass = (severity) => `sev sev-${severity.toLowerCase()}`;
