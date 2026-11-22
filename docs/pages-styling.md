# Documentation portal styling

Forgejo Pages uses the application's actual `nergal.css` stylesheet and early
`theme.js` initialization. The shared masthead, brand mark, font stacks, emerald
accent, light/dark surfaces, borders, buttons and focus styles therefore have the
same source as the management UI. `pages/assets/nergal-theme.css` adapts Docsify's
sidebar, search, article cards, tables and code blocks to those application tokens.
`portal.js` provides the theme button, active navigation, responsive masthead sizing
and Mermaid rendering using the current colors. Theme preference is saved per
origin; the application and Pages can have independent choices on different origins.

After changing application styling or theme initialization, run:

```sh
python3 scripts/pages_assets.py
python3 scripts/verify-pages.py
node --test scripts/pages-theme.test.mjs
```

Commit the generated `pages/assets/application.css` and `pages/assets/theme.js`
with their source changes. CI and the Pages publishing workflow reject stale
copies. Theme-control tests cover saved preferences overriding system appearance,
system appearance before an explicit choice, and storage-denial fallback.

Preview public documentation only:

```sh
python3 -m http.server 8766 --bind 127.0.0.1 --directory pages
```

Browser checks cover light/dark switching and reload persistence, search results,
article navigation, diagrams in both themes, tables/code, keyboard skip navigation,
and the menu and content width at a 390px mobile viewport. Screenshots in
`pages/assets/screenshots/pages-*.jpg` show synthetic/public documentation only.
This change does not alter authentication, roles, policy semantics or agent access.
