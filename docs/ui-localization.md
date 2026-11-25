# MVC display languages

The provisional MVC locales are English (`en-US`) and Spanish (`es-ES`). Spanish
coverage includes sign-in, the shared shell and navigation, Overview guidance
and host observations, the Hosts registration form and its validation, the
OAuth connection form, audit history, standalone browser errors, and shared
MVC timestamps. Both locales exercise the translation
workflow while launch languages remain undecided. Other views can still contain
English copy.

Open **Language** in the top bar, choose a language, and select **Set language**.
The control works before sign-in and with JavaScript disabled. It saves a
host-only browser preference for 180 days. A missing, expired, or unsupported
cookie selects English. Browser preference headers and URL parameters have no
effect. The antiforgery-protected POST redirects to a local page. A switch from
a normal GET returns to the page path with a fresh GET. Query parameters,
fragments, and form drafts are outside the preference request.

## Resource convention

Inject `IStringLocalizer<Nergal.Web.UiStrings>` in Razor views and pass English
source strings as keys. The English source is also the fallback for each missing
translation. Place plain-text translations in `src/Nergal.Web/Resources/UiStrings.<locale>.resx`.
Resource keys must be unique regardless of casing. Use one key for each message
and keep positional placeholders so translators can reorder their arguments.
Let Razor HTML-encode translated strings and arguments. Use the same convention
for visible text, document titles, accessible names, and hints. Set
`ViewData["LocalizedContent"] = true` in a translated view so the layout can
identify the selected language to assistive technology. The layout identifies
English body content separately on views that have yet to translate their copy.

Apply locale formatting to display values such as the counts on the Hosts and
Audit pages. Keep form field names and tokens, identifiers, fingerprints,
diagnostic codes, audit values, and transport data in their existing machine
representations. Translate a status label at rendering time and preserve the
underlying classification. The selected language controls MVC text and browser
timestamp formatting. The browser timezone controls the displayed offset. See
[timestamp storage and display](time-display.md).

## Verification

`UiLocalizationTests` covers the explicit cookie allowlist, default and missing
message fallback, Spanish validation/status resources, and local redirect safety.
After a Release build, run `python3 -B tests/integration/local-sessions/check-localization.py`
for the real HTTPS selector, antiforgery, validation, host status, and audit UTC
markup. Run `node --test scripts/local-time.test.mjs scripts/app-theme.test.mjs`
for locale-sensitive time and theme labels. Browser acceptance includes keyboard
language selection and readable expanded labels in Spanish on the Hosts form and
navigation at desktop and narrow mobile widths in light and dark modes.
