/* Documentation layout and theme controls. Shared colors and initial preference come from the application assets. */
(function () {
  "use strict";
  const root = document.documentElement;
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const isDark = () => root.getAttribute("data-theme") === "dark" ||
    (!root.getAttribute("data-theme") && systemTheme.matches);
  const toggle = document.querySelector("[data-theme-toggle]");
  const updateButton = () => {
    toggle.textContent = isDark() ? "Light mode" : "Dark mode";
    toggle.setAttribute("aria-label", "Switch to " + (isDark() ? "light" : "dark") + " theme");
  };
  document.querySelector(".skip-link").addEventListener("click", event => {
    event.preventDefault();
    document.querySelector(".markdown-section")?.focus();
  });
  let renderQueue = Promise.resolve();
  const renderDiagrams = () => {
    renderQueue = renderQueue.then(async () => {
      if (!window.mermaid) return;
      const nodes = [...document.querySelectorAll(".mermaid")];
      if (!nodes.length) return;
      const style = getComputedStyle(root);
      const color = name => style.getPropertyValue(name).trim();
      window.mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: "base",
        themeVariables: { darkMode: isDark(), fontFamily: color("--font-sans"),
          background: color("--surface"), primaryColor: color("--surface-subtle"),
          primaryTextColor: color("--text"), primaryBorderColor: color("--border-strong"),
          lineColor: color("--text-muted"), secondaryColor: color("--surface"),
          tertiaryColor: color("--surface-subtle"), edgeLabelBackground: color("--surface") }
      });
      for (const node of nodes) {
        node.dataset.source ||= node.textContent;
        node.textContent = node.dataset.source;
        node.removeAttribute("data-processed");
      }
      try { await window.mermaid.run({ nodes }); }
      catch { for (const node of nodes) node.textContent = node.dataset.source; }
    });
    return renderQueue;
  };
  toggle.addEventListener("click", () => {
    const next = isDark() ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("nergal-theme", next); } catch { /* Theme switching works with storage disabled. */ }
    updateButton();
    renderDiagrams();
  });
  systemTheme.addEventListener("change", () => { updateButton(); renderDiagrams(); });
  updateButton();
  const updateNavigation = () => {
    const current = location.hash.replace(/\?.*$/, "").replace(/\.md$/, "").replace(/\/$/, "").replace(/^#\/(?:README|index)$/, "#") || "#";
    document.querySelectorAll(".docs-topbar .nav-link").forEach(link => {
      const active = link.getAttribute("href").replace(/\/$/, "") === current;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
    });
    const main = document.querySelector(".markdown-section");
    if (main) { main.id = "main"; main.tabIndex = -1; }
  };
  // Account for the actual wrapped masthead, including zoom and narrow viewports.
  new ResizeObserver(entries => {
    root.style.setProperty("--masthead-height", entries[0].target.getBoundingClientRect().height + "px");
  }).observe(document.querySelector(".docs-topbar"));
  window.nergalDocs = { renderDiagrams, updateNavigation };
})();
