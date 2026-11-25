// Appliance navigation is progressive enhancement; ordinary links remain usable without JavaScript.
(() => {
  const toggle = document.querySelector('[data-sidebar-toggle]');
  const sidebar = document.getElementById('management-navigation');
  if (!toggle || !sidebar) return;
  document.documentElement.setAttribute('data-navigation-ready', 'true');
  const close = () => {
    toggle.setAttribute('aria-expanded', 'false');
    sidebar.removeAttribute('data-open');
  };
  toggle.addEventListener('click', () => {
    const opening = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.setAttribute('aria-expanded', String(opening));
    if (opening) sidebar.setAttribute('data-open', 'true'); else close();
  });
  const dismiss = event => {
    if (event.key === 'Escape') { close(); toggle.focus(); }
  };
  toggle.addEventListener('keydown', dismiss);
  sidebar.addEventListener('keydown', dismiss);
  document.addEventListener('click', event => {
    const link = event.target.closest('[data-open-details]');
    const href = link?.getAttribute('href');
    if (!href?.startsWith('#')) return;
    const details = document.getElementById(href.slice(1));
    if (details?.tagName !== 'DETAILS') return;
    event.preventDefault();
    details.open = true;
    details.querySelector('summary').focus();
    details.scrollIntoView({ block: 'start' });
  });
  sidebar.addEventListener('click', event => {
    const link = event.target.closest('[data-policy-section]');
    if (!link) return;
    const section = link.getAttribute('data-policy-section');
    // Click the existing local section control, preserving every unsaved field and pinned draft.
    const button = [...document.querySelectorAll('[data-tab-target]')].find(item => item.getAttribute('data-tab-target') === section);
    if (!button) return;
    event.preventDefault();
    button.click();
    close();
    button.focus();
  });
})();
