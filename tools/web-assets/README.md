# Locally bundled code editor

The policy JSON authoring field uses CodeMirror 6. The browser loads only the
committed local bundle, with no CDN or runtime package download. The textarea is
retained for progressive enhancement and server form binding. Editor updates
synchronize its value; preview/save still pass through CSRF, role checks and strict
server policy validation. The editor's JSON lint is syntax guidance, not authority
to apply a policy. Indentation preserves tokens, including duplicate keys that the
server must reject, rather than silently reserializing them.

Using Node.js 24 and npm, rebuild after changing the editor or dependencies:

```sh
npm ci --prefix tools/web-assets --ignore-scripts
npm run build --prefix tools/web-assets
npm test --prefix tools/web-assets
npm run verify --prefix tools/web-assets
```

Commit `package-lock.json`, the bundle and generated license notices together.
Ordinary .NET builds and packaged installations do not need Node.js. CI verifies
that locked dependencies reproduce the committed assets. CodeMirror includes line
numbers, syntax highlighting, folding, history, bracket matching, search and JSON
syntax diagnostics. Tab retains normal focus navigation; Enter indents lines, and
**Indent lines** uses the parser's indentation rules. All colors follow the console
light/dark theme, including changes while an editor is open.

The policy view supplies editor labels and CodeMirror phrases in Razor-encoded
data attributes using the same UI resource localizer as the surrounding form.
CodeMirror substitutes line numbers and match counts in phrases containing `$`.

Browser QA should cover invalid JSON retention and diagnostics, edited text posted
to preview, syntax valid but unsupported policy denial, duplicate-key rejection,
keyboard navigation, search, both themes and a narrow mobile viewport. Public
screenshots must contain only synthetic policy data.
