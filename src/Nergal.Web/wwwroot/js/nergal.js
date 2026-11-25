/* Progressive-enhancement UI behaviors for nergal (all forms remain fully functional without JS). */
(function () {
  "use strict";

  // 1. Describe the action in both themes, including initial/system changes, as Pages does.
  const root = document.documentElement;
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const isDark = () => root.getAttribute("data-theme") === "dark" ||
    (!root.getAttribute("data-theme") && systemTheme.matches);
  const updateThemeButtons = () => {
    document.querySelectorAll("[data-theme-toggle]").forEach(toggle => {
      toggle.textContent = isDark() ? "Light mode" : "Dark mode";
      toggle.setAttribute("aria-label", "Switch to " + (isDark() ? "light" : "dark") + " theme");
    });
  };
  document.addEventListener("click", function (e) {
    if (!e.target.closest("[data-theme-toggle]")) return;
    const next = isDark() ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("nergal-theme", next); } catch { /* Storage can be disabled. */ }
    updateThemeButtons();
  });
  systemTheme.addEventListener("change", updateThemeButtons);
  updateThemeButtons();

  // 2. Register Host form: toggle Unix vs TLS fields based on transportKind.
  const transportSelect = document.querySelector("[data-transport-select]");
  if (transportSelect) {
    const syncTransport = function () {
      const mode = transportSelect.value;
      document.querySelectorAll("[data-transport-only]").forEach(function (el) {
        el.classList.toggle("hidden", el.getAttribute("data-transport-only") !== mode);
      });
    };
    transportSelect.addEventListener("change", syncTransport);
    syncTransport();
  }

  // 3. Page tabs (remembers active tab per page path in sessionStorage across form posts).
  const tabButtons = document.querySelectorAll("[data-tab-target]");
  if (tabButtons.length > 0) {
    const tabScope = document.querySelector("[data-tab-scope]");
    const tabStorageKey = "nergal-tab:" + (tabScope?.getAttribute("data-tab-scope") || window.location.pathname);
    const activateTab = function (id) {
      tabButtons.forEach(function (btn) {
        const active = btn.getAttribute("data-tab-target") === id;
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-selected", active ? "true" : "false");
        btn.setAttribute("tabindex", active ? "0" : "-1");
      });
      document.querySelectorAll("[data-policy-section]").forEach(function (link) {
        const active = link.getAttribute("data-policy-section") === id;
        link.classList.toggle("active", active);
        if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
      });
      document.querySelectorAll("[data-tab-panel]").forEach(function (panel) {
        panel.classList.toggle("hidden", panel.getAttribute("data-tab-panel") !== id);
      });
      try { sessionStorage.setItem(tabStorageKey, id); } catch { /* Tabs also work with storage disabled. */ }
    };

    tabButtons.forEach(function (btn, index) {
      const target = btn.getAttribute("data-tab-target");
      const panel = [...document.querySelectorAll("[data-tab-panel]")].find(item => item.getAttribute("data-tab-panel") === target);
      if (panel) {
        panel.id = target;
        btn.id = "control-" + target;
        btn.setAttribute("aria-controls", target);
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", btn.id);
      }
      btn.addEventListener("click", function () { activateTab(target); });
      btn.addEventListener("keydown", function (event) {
        let next;
        if (event.key === "ArrowRight") next = (index + 1) % tabButtons.length;
        if (event.key === "ArrowLeft") next = (index - 1 + tabButtons.length) % tabButtons.length;
        if (event.key === "Home") next = 0;
        if (event.key === "End") next = tabButtons.length - 1;
        if (next === undefined) return;
        event.preventDefault();
        activateTab(tabButtons[next].getAttribute("data-tab-target"));
        tabButtons[next].focus();
      });
    });

    let initialTab = tabScope?.getAttribute("data-initial-tab");
    if (!initialTab) {
      try { initialTab = sessionStorage.getItem(tabStorageKey); } catch { /* Use the first tab. */ }
    }
    if (initialTab && document.querySelector('[data-tab-panel="' + initialTab + '"]')) {
      activateTab(initialTab);
    } else {
      activateTab(tabButtons[0].getAttribute("data-tab-target"));
    }
  }

  // 4. Filter rule builder: toggle port vs ICMP type fields based on protocol.
  const protoSelect = document.querySelector("[data-filter-protocol]");
  if (protoSelect) {
    const syncProto = function () {
      const p = protoSelect.value;
      const isTransport = p === "tcp" || p === "udp";
      const isIcmp = p === "icmp" || p === "icmpv6";
      document.querySelectorAll("[data-proto-group='transport']").forEach(function (el) {
        el.classList.toggle("hidden", !isTransport);
      });
      document.querySelectorAll("[data-proto-group='icmp']").forEach(function (el) {
        el.classList.toggle("hidden", !isIcmp);
      });
    };
    protoSelect.addEventListener("change", syncProto);
    syncProto();
  }

  // 5. Connection-state checkboxes -> hidden comma-separated connectionStates field.
  const stateCheckboxes = document.querySelectorAll("[data-ct-state-cb]");
  const stateTarget = document.querySelector("[data-ct-state-value]");
  if (stateCheckboxes.length > 0 && stateTarget) {
    const syncStates = function () {
      const selected = [];
      stateCheckboxes.forEach(function (cb) {
        if (cb.checked) selected.push(cb.value);
      });
      stateTarget.value = selected.join(", ");
    };
    stateCheckboxes.forEach(function (cb) {
      cb.addEventListener("change", syncStates);
    });
  }

  // 6. Live client-side watchdog countdown on Confirmed Apply page.
  const countdownEl = document.querySelector("[data-countdown-seconds]");
  if (countdownEl) {
    const total = Math.max(1, parseInt(countdownEl.getAttribute("data-countdown-seconds") || "0", 10));
    let remaining = total;
    const fill = document.querySelector("[data-countdown-fill]");
    const tick = function () {
      countdownEl.textContent = remaining + " s remaining";
      if (fill) {
        fill.style.width = Math.max(0, Math.min(100, (remaining / total) * 100)) + "%";
      }
      if (remaining > 0) {
        remaining -= 1;
        window.setTimeout(tick, 1000);
      }
    };
    tick();
  }

  // 7. Client-side filter input for Audit log table.
  const auditFilter = document.querySelector("[data-audit-filter]");
  if (auditFilter) {
    auditFilter.addEventListener("input", function () {
      const q = auditFilter.value.trim().toLowerCase();
      document.querySelectorAll("[data-audit-row]").forEach(function (row) {
        row.classList.toggle("hidden", q.length > 0 && !row.textContent.toLowerCase().includes(q));
      });
    });
  }
})();
