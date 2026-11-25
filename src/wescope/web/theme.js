// 첫 화면 테마 깜빡임 방지: CSS보다 먼저 <html data-theme>를 정한다 (DASHBOARD.md §2-4).
// 저장값 "system" | "light" | "dark", 기본 system. 원본은 전역 설정(GET /api/settings)이고, localStorage는 첫 화면용 사본이다.
(function () {
  var dark = window.matchMedia("(prefers-color-scheme: dark)");
  function saved() {
    try { return localStorage.getItem("wescope.theme") || "system"; } catch (e) { return "system"; }
  }
  function apply() {
    var pick = saved();
    document.documentElement.dataset.theme = pick === "system" ? (dark.matches ? "dark" : "light") : pick;
  }
  apply();
  dark.addEventListener("change", apply);
  window.setTheme = function (pick) {   // app.js가 서버 설정을 받으면 부른다
    try { localStorage.setItem("wescope.theme", pick); } catch (e) { /* 저장 못 해도 이번 화면엔 적용 */ }
    document.documentElement.dataset.theme = pick === "system" ? (dark.matches ? "dark" : "light") : pick;
  };
})();
