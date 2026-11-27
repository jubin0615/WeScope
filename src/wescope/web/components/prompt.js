// 수정 요청 프롬프트: AI 코딩 도구에 붙여 넣을 문장을 묶음 하나로 만든다 (DASHBOARD.md §7, AI.md §3-6).
// 근거 코드(evidence)는 넣지 않는다 — 마스킹돼 있어도 비밀값 조각이 섞일 수 있어서. diff는 서버가 가린 그대로 쓴다.
import { groupFix } from "./list.js";

const MAX_PLACES = 10;
const VERIFY_PROMPT = {
  verified: "We-Scope 검증됨: 적용·문법·재검사 통과",
  partial: "We-Scope 문법 확인: 재검사로는 확인 못 함",
  failed: "검증 안 됨: 참고용",
};

export function place(f) {
  const { file, line, route } = f.location;
  const base = line > 0 ? `${file}:${line}` : file;
  return route ? `${base} (${route})` : base;
}

export function buildPrompt({ repo, result, group }) {
  const f = group.findings[0];
  const fix = groupFix(group);
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
  ];
  if (fix?.diff) lines.push(`제안 수정 (${VERIFY_PROMPT[fix.verification] ?? VERIFY_PROMPT.failed}):`, "```diff", fix.diff.trimEnd(), "```");
  else {
    lines.push(`수정 방법: ${f.fix_ko}`);
    if (f.fix_example) lines.push("수정 예시:", "```", f.fix_example.trimEnd(), "```");
  }
  lines.push("", "지켜야 할 것:",
    "- 위 수정을 우선 적용하고, 프로젝트 사정상 다르게 고쳐야 하면 같은 원칙을 지키세요.");
  if (f.avoid_ko) lines.push(`- 하지 말 것: ${f.avoid_ko}`);
  if (f.category === "WS-01") lines.push("- 노출된 키는 코드만 고치지 말고 발급처에서 폐기·재발급하세요.");
  lines.push("- 함수 이름·응답 형식은 바꾸지 마세요.",
    "- 고친 뒤 무엇을 바꿨는지 파일별로 짧게 알려 주세요.");
  if (fix?.follow_ups?.length) lines.push(`코드 밖에서 할 일: ${fix.follow_ups.join(" / ")}`);
  lines.push("확인: 다시 스캔하면 We-Scope가 해결 여부를 확인해요.");
  return lines.join("\n");
}
