/* Select the theme before first paint; storage denial must not disable the UI. */
(function () {
  "use strict";
  const root = document.documentElement;
  let theme = root.getAttribute("data-default-theme");
  try { theme = localStorage.getItem("nergal-theme") || theme; } catch { /* Use the configured default. */ }
  if (theme === "light" || theme === "dark") root.setAttribute("data-theme", theme);
})();
