// 화면이 쓰는 한국어 표기. src/wescope/report/wording.py와 같은 문자열이어야 한다 (tests/test_report.py가 확인).
export const STATE_KO = {"vulnerable": "취약 후보", "clean": "검사함 · 미발견", "partial": "부분 점검", "not_applicable": "해당 없음", "skipped": "건너뜀", "manual": "수동 확인 필요"};
export const ANALYZER_STATUS_KO = {"ok": "정상", "partial": "일부만 검사", "skipped": "건너뜀", "failed": "실패", "not_applicable": "해당 없음"};
export const CHANGE_KO = {"new": "NEW", "existing": "직전 검사에도 있음", "fixed": "FIXED", "unknown": "확인 불가 (파일을 읽지 못함)"};
export const OWASP_SCOPE_TITLE = "OWASP Top 10:2025 분류 기준 점검 범위";
export const NOT_A_GUARANTEE = "정적 분석으로 찾은 위험 '후보'예요. 이 보고서는 안전을 보증하지 않아요. 검사하지 못한 영역은 '건너뜀'·'부분 점검'·'수동 확인 필요'로 표시했어요.";
export const LIMITS = ["같은 함수 안의 흐름만 확인했어요. 여러 파일을 거치는 흐름과 업무 로직(결제·권한 정책)은 정적 분석으로 보기 어려워요.", "'Potential' 발견은 보호 코드가 없어 보인다는 추정이에요. 상위 미들웨어·게이트웨이·DB 정책을 직접 확인하세요.", ".env·키 파일은 내용을 열지 않고 경로와 Git 상태만 확인했어요.", "실행 중인 서비스는 검사하지 않았어요. 보안 헤더·실제 응답은 따로 확인해야 해요."];
