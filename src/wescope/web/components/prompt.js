// 수정 요청 프롬프트: AI 코딩 도구에 붙여 넣을 문장을 묶음 하나로 만든다 (DASHBOARD.md §7, AI.md §3-6).
// 근거 코드(evidence)는 넣지 않는다 — 마스킹돼 있어도 비밀값 조각이 섞일 수 있어서.
// shortcut: ChatGPT 수정안(fix.diff·검증 상태·follow_ups)이 없는 기본 형식만. B8에서 fix가 생기면 "제안 수정" 블록을 붙인다.

const MAX_PLACES = 10;

export function place(f) {
  const { file, line, route } = f.location;
  const base = line > 0 ? `${file}:${line}` : file;
  return route ? `${base} (${route})` : base;
}

export function buildPrompt({ repo, result, group }) {
  const f = group.findings[0];
  const where = [repo.branch, result.commit?.slice(0, 7)].filter(Boolean).join(" · ");
  const tags = [group.severity, f.cwe, f.owasp && `OWASP ${f.owasp}`].filter(Boolean).join(" · ");
  const places = group.findings.slice(0, MAX_PLACES).map(place).join(", ")
    + (group.findings.length > MAX_PLACES ? ` 외 ${group.findings.length - MAX_PLACES}곳` : "");
  const lines = [
    "[We-Scope 보안 수정 요청]",
    `프로젝트: ${repo.name}${where ? ` (${where})` : ""}`,
    `문제: ${f.tech_name_ko} — ${tags}`,
    `위치: ${places}`,
    `왜 위험한가: ${f.why_ko}`,
    "",
    `수정 방법: ${f.fix_ko}`,
  ];
  if (f.fix_example) lines.push("수정 예시:", "```", f.fix_example.trimEnd(), "```");
  lines.push("", "지켜야 할 것:",
    "- 위 방법을 우선 적용하고, 프로젝트 사정상 다르게 고쳐야 하면 같은 원칙을 지키세요.");
  if (f.avoid_ko) lines.push(`- 하지 말 것: ${f.avoid_ko}`);
  if (f.category === "WS-01") lines.push("- 노출된 키는 코드만 고치지 말고 발급처에서 폐기·재발급하세요.");
  lines.push("- 함수 이름·응답 형식은 바꾸지 마세요.",
    "- 고친 뒤 무엇을 바꿨는지 파일별로 짧게 알려 주세요.",
    "확인: 다시 스캔하면 We-Scope가 해결 여부를 확인해요.");
  return lines.join("\n");
}
