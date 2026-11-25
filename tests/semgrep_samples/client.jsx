// 브라우저 코드 표본
import DOMPurify from "dompurify";

export function Comment({ html }) {
  // ruleid: inject-xss
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function SafeComment({ html }) {
  // ok: inject-xss
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function showHash() {
  const el = document.getElementById("out");
  // ruleid: inject-xss
  el.innerHTML = location.hash.slice(1);
  // ok: inject-xss
  el.textContent = location.hash.slice(1);
  const next = new URLSearchParams(location.search).get("next");
  // ruleid: inject-open-redirect
  window.location.href = next;
}
