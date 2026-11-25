/* Stored/API instants remain UTC. Only presentation uses the viewer's locale/timezone. */
(function () {
  "use strict";
  const selector = "time[data-local-time]";
  const utcPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z$/;

  function formatter() {
    try {
      const locale = document.documentElement.getAttribute("data-ui-locale") || undefined;
      return new Intl.DateTimeFormat(locale, {
        year: "numeric", month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short",
      });
    } catch { return null; }
  }

  function render(element, format) {
    const instant = element.getAttribute("datetime");
    if (!instant || instant.length > 35 || !utcPattern.test(instant)) return;
    const date = new Date(instant);
    // Reject normalized invalid calendar dates instead of silently changing the instant.
    if (!Number.isFinite(date.valueOf()) || date.toISOString().slice(0, 19) !== instant.slice(0, 19)) return;
    try {
      const text = format.format(date);
      if (element.textContent !== text) element.textContent = text;
    } catch { /* Retain the explicit UTC fallback. */ }
  }

  function renderTree(root, format) {
    if (!format) return;
    if (root.matches?.(selector)) render(root, format);
    root.querySelectorAll?.(selector).forEach(element => render(element, format));
    const zone = format.resolvedOptions().timeZone;
    if (root.matches?.("[data-local-time-zone]")) root.textContent = zone;
    root.querySelectorAll?.("[data-local-time-zone]").forEach(element => { element.textContent = zone; });
  }

  function refresh() { renderTree(document, formatter()); }
  refresh();
  window.addEventListener("focus", refresh);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  // Also handles timestamps rendered later by interactive Blazor components.
  if (typeof MutationObserver !== "undefined") {
    new MutationObserver(records => {
      const format = formatter();
      for (const record of records) {
        if (record.type === "attributes") renderTree(record.target, format);
        else {
          if (record.target?.matches?.(selector)) renderTree(record.target, format);
          for (const node of record.addedNodes) if (node.nodeType === 1) renderTree(node, format);
        }
      }
    }).observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ["datetime"] });
  }
})();
