// 첫 화면 테마 깜빡임 방지: CSS보다 먼저 <html data-theme>를 정한다 (DASHBOARD.md §2-4).
// 저장값 "system" | "light" | "dark", 기본 system. shortcut: 브라우저 localStorage에 둔다, 전역 설정 API가 생기면 옮긴다 (DASHBOARD.md §8-2).
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
})();
