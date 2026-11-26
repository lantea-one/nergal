# MVC display languages

The console offers 20 display languages. Each catalog covers the registered
console messages, including management forms, local and federated sign-in,
authenticator recovery, verification-code emails, policy review, confirmed apply,
and the JSON editor's controls. Arabic and Hebrew render localized pages right to
left. JSON, recovery keys, and numeric authenticator codes retain left-to-right order.

The choices are English, Arabic, Chinese (Simplified and Traditional), Dutch,
French, German, Hebrew, Hindi, Indonesian, Italian, Japanese, Korean, Polish,
Portuguese (Brazil), Russian, Spanish, Turkish, Ukrainian and Vietnamese.

The catalogs combine authored and machine-assisted translations. Placeholders and
technical literals were checked, and consequential firewall and identity messages
received additional review. Independent native-speaker review across the full
catalogs is pending. Native source, diagnostic identifiers, operator-provided
values, and browser or parser diagnostics retain their original representations. English is the fallback for
messages outside the resource catalogs.

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
`ViewData["LocalizedContent"] = true` in a view that renders its body from the
resource catalogs. Use logical CSS properties for placement that follows the
writing direction and isolate machine-readable values where their order matters.

To add a language, add its exact culture and native display name to `UiLocalization`
and translate a matching `UiStrings.<culture>.resx` for the full message set.
Preserve placeholders and protocol names. Run the localization tests before
making the language available in the selector.

Run `python3 -B scripts/check-ui-catalogs.py` for per-locale counts and structural
validation. `--json` reports the exact missing messages. CI uses
`--require-complete` to reject gaps across supported locales. The inventory counts literal
resource lookups and catalog entries. Review computed messages, plain text in
templates, and dependency-provided text as well. Review firewall and identity
instructions for meaning in each language before publishing translations.

Apply locale formatting to display values such as the counts on the Hosts and
Audit pages. Keep form field names and tokens, identifiers, fingerprints,
diagnostic codes, audit values, and transport data in their existing machine
representations. Translate a status label at rendering time and preserve the
underlying classification. The selected language controls MVC text and browser
timestamp formatting. The browser timezone controls the displayed offset. See
[timestamp storage and display](time-display.md).

## Verification

`UiLocalizationTests` covers the explicit cookie allowlist, shared coverage for
each selectable locale, fallback, Spanish validation/status resources, and local
redirect safety.
After a Release build, run `python3 -B tests/integration/local-sessions/check-localization.py`
for the real HTTPS selector, antiforgery, right-to-left sign-in, language and
direction in fallback views, validation, host status, and audit UTC markup. Run
`node --test scripts/local-time.test.mjs scripts/app-theme.test.mjs`
for locale-sensitive time and theme labels. Browser acceptance includes keyboard
language selection, Spanish Hosts and source workflows, and Arabic navigation at
desktop and narrow mobile widths.
