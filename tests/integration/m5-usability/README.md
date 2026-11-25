# M5 cross-workflow browser acceptance

Run from the repository root after the current checkout has a Release build. Use
a regular Linux user, Python 3, OpenSSL, the pinned .NET runtime, and an installed
Chromium or Chrome with a matching ChromeDriver. The harness uses local
ChromeDriver and Python's standard library. It installs no browser or Python
packages. Keep the build outputs and web assets stable during the run.

```sh
python3 -B tests/integration/m5-usability/check.py
```

If the matching browser and driver are outside `PATH`, set `CHROMIUM_BIN` and
`CHROMEDRIVER_BIN` to their executable paths. The harness reads the existing
`net10.0` Release outputs for `Nergal.Web` and `Nergal.Admin`. The HTTPS fixture
uses the build's static web assets manifest and the checkout's web assets.

Each invocation provisions fresh synthetic accounts, keys, certificates and a
SQLite controller in a private temporary directory. It starts the real controller
over loopback HTTPS and trusts the disposable certificate via its public-key pin
in a fresh headless browser profile. The only registered endpoint is a Unix
socket path inside that directory with no listener. Browser requests to the
apply, confirm and rollback mutation routes are blocked. All persisted UI edits
are confined to the disposable stores, which are removed at shutdown.

The checkpoints cover:

- Anonymous entry, local sign-in, policy-first guidance, visible skip-link focus,
  and focus transfer to the main landmark.
- A guided filtering rule, contextual hints, unfinished fields and change note across
  sidebar switches, arrow-key tabs, Add Rule and preview with no saved revision, and a separate
  revision save followed by connection guidance.
- Transport-specific registration fields, the enrollment prerequisite, and
  unavailable status for the disposable connection.
- Source upload, explicit table mapping, a source-positioned conversion denial,
  and separate review and commit of a supported source. Review does not create a
  revision.
- The administrator's target and revision selection, CSRF token, bounded timeout,
  watchdog guidance, and read-only status refresh, plus the Auditor's read-only
  apply view and authorization denial on restricted pages.
- Authentication settings links for OIDC, LDAP, profile defaults, MFA, email
  delivery and recovery. Local Auditor creation, profile editing and sign-out
  are exercised with the synthetic accounts.
- Desktop light and dark themes at 1440 × 1000, browser timezone display, and
  mobile navigation and page-width checks at 375 × 812, including keyboard
  opening, Escape dismissal and restored focus.

The command returns a nonzero status on failure. Its printed directory under
`artifacts/m5-usability/` contains `results.json` with assembly hashes, the
Chromium version and named checkpoint results, plus PNG checkpoints and a
failure screenshot when the browser remains available. Review the images for
visual issues beyond the assertions. Screenshot position can reflect the last
interaction that brought a control into view.

The harness exercises English navigation and Spanish Hosts at 375 px, and verifies English fallback on Native sources. Identity provider
authentication, MFA enrollment/delivery/recovery, translation quality, live
pending confirmations, kernel observations, packet behavior and timed rollback
require their corresponding checks.
