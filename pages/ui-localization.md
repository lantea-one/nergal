# MVC display languages

The console offers 20 display languages. Every language covers the shared shell,
navigation and sign-in, including the local, LDAP, OAuth and OIDC options. Arabic
and Hebrew render the shell and sign-in right to left.

The choices are English, Arabic, Chinese (Simplified and Traditional), Dutch,
French, German, Hebrew, Hindi, Indonesian, Italian, Japanese, Korean, Polish,
Portuguese (Brazil), Russian, Spanish, Turkish, Ukrainian and Vietnamese.

Spanish also covers Overview and host observations, Hosts registration and
validation, the OAuth connection form, audit history, browser errors, sign-in
verification and recovery, native source import and conversion review, and key
policy review and confirmed-apply controls. English is the fallback for views and
messages outside a catalog's coverage. Untranslated main content explicitly
declares English and left-to-right direction so assistive technology can interpret
it correctly.

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
`ViewData["LocalizedContent"] = true` in a view covered by the extended Spanish
catalog. Use `ViewData["LocalizedForAllLanguages"] = true` only for views fully
covered by every supported language. Mark individual translated regions with
their language when working on a view incrementally. Use logical CSS properties
for placement that follows the writing direction.

To add a language, add its exact culture and native display name to `UiLocalization`
and create a matching `UiStrings.<culture>.resx` with the shared navigation and
sign-in messages from a shipped catalog. Preserve placeholders and protocol names.
Run the localization tests before making the language available in the selector.

Apply locale formatting to display values such as the counts on the Hosts and
Audit pages. Keep form field names and tokens, identifiers, fingerprints,
diagnostic codes, audit values, and transport data in their existing machine
representations. Translate a status label at rendering time and preserve the
underlying classification. The selected language controls MVC text and browser
timestamp formatting. The browser timezone controls the displayed offset. See
the UTC time contract in [Architecture](architecture.md).

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
