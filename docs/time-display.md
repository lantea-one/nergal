# Timestamp storage and display

Application timestamps are stored as UTC instants. Controller host creation,
policy revisions, settings updates, native imports and audit records normalize
incoming offsets before persistence. API timestamps and machine-readable HTML
`datetime` attributes remain UTC; presentation does not rewrite stored values.

Management screens format timestamps using the selected MVC display language and
the viewer's browser timezone, including a timezone indication. Shared displays
outside the MVC layout use the browser's locale. The shared MVC time partial and
Blazor component emit the original UTC instant, and the local formatter enhances
its visible text. See [MVC display languages](ui-localization.md).
This covers dashboard/apply audit rows, audit history, revision history and native
source imports. The navigation names the browser's IANA timezone. Returning to the page
refreshes presentation if the system timezone changed.

Daylight-saving transitions use the offset applicable to the stored instant, not
the current offset. Repeated autumn hours retain timezone abbreviations. The UTC
instant remains available in the timestamp tooltip for correlation. Missing Intl,
invalid input or JavaScript-disabled operation retains explicitly labeled UTC;
the server timezone is never silently used as the viewer's timezone.

`node --test scripts/local-time.test.mjs` checks Spanish formatting with a browser
timezone outside Spain, date boundaries, spring/autumn DST,
half-hour and southern-hemisphere offsets, malformed/ambiguous input, fallback,
interactive component updates and changed viewer timezone using real Intl data.
SQLite tests inject an offset-bearing clock and verify UTC persistence across all
controller timestamp fields. No timezone-specific database migration is needed for
the existing normalized UTC records. This does not change monotonic apply deadlines.
