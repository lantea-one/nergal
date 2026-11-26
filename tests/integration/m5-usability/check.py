"""Exercise M5 operator journeys against a fresh, unprivileged HTTPS controller."""

import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import traceback

from chromium import launch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "local-sessions"))
from check import ADMIN_TOOL, DLL, PASSWORD, ROOT, host, provision

NAV = "#management-navigation"
TAB = "\ue004"
ENTER = "\ue007"
ESCAPE = "\ue00c"
RIGHT = "\ue014"
START = 'form[action="/manage/apply/start"]'
APPLY_MUTATIONS = 'form[method=post][action^="/manage/apply/"]'
POLICY_NOTE = 'M5 guided policy"><span id="revision-note-probe">'


def link(path, scope=NAV):
    return f'{scope} a[href="{path}"]'


def submit(action):
    return f'form[action="{action}"] button[type=submit]'


def expect_text(browser, fragment, selector="main"):
    browser.wait_for(lambda: fragment in browser.text(selector), f"Expected {fragment!r} in {selector}")


def focus_is_visible(browser, selector):
    assert browser.evaluate("""
        const active = document.activeElement;
        const style = getComputedStyle(active);
        const outline = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0;
        return active.matches(arguments[0]) && active.matches(':focus-visible')
            && (outline || style.boxShadow !== 'none');
    """, selector), f"Expected visible keyboard focus on {selector} at {browser.path()}"


def login(browser, username):
    assert browser.path() == "/login"
    browser.fill("#login-username", username)
    browser.fill("#login-password", PASSWORD)
    browser.click(submit("/login"))
    browser.wait_for_path("/manage")
    expect_text(browser, "Overview", "h1")


def rows(state, sql):
    with closing(sqlite3.connect((state / "controller.db").as_uri() + "?mode=ro", uri=True)) as db:
        return db.execute(sql).fetchall()


def revisions(state):
    return rows(state, "SELECT revision, summary FROM policy_revisions ORDER BY revision")


def first_use(browser, origin, state, capture):
    browser.post("/url", url=origin + "/")
    assert browser.path() == "/login", "Anonymous root did not lead to sign-in"
    expect_text(browser, "Sign in", "h1")
    assert browser.evaluate("""
        return !!document.querySelector('link[href*="/css/nergal.css"]').sheet
            && document.querySelector('[data-theme-toggle]').hasAttribute('aria-label');
    """), "The fixture did not load the compiled site's local stylesheet and theme script"
    capture("sign-in-light")
    login(browser, "fixture-admin")
    expect_text(browser, "Start with your firewall policy", "#next-action-heading")
    assert browser.visible(link("/manage/sources", ".next-action"))
    assert browser.visible(NAV + ' a[href="/manage"][aria-current="page"]')
    expect_text(browser, "No saved policy yet")
    expect_text(browser, "No hosts connected")
    browser.key(TAB)
    focus_is_visible(browser, ".skip-link")
    assert browser.evaluate("return document.activeElement.getBoundingClientRect().top >= 0;")
    browser.key(ENTER)
    assert browser.evaluate("return document.activeElement.id;") == "main-content"
    assert rows(state, "SELECT action FROM audit_log") == [], "First-use navigation wrote controller audit"
    capture("overview-light")


def create_policy(browser, state, capture):
    audit_before = rows(state, "SELECT * FROM audit_log")
    browser.click(link("/manage/policies", ".next-action"))
    expect_text(browser, "Firewall", "h1")
    assert not browser.visible(".cm-editor"), "The raw code editor opened by default"
    browser.click('[data-open-details][href="#new-filter-rule"]')
    assert browser.visible("#new-filter-rule form"), "Add rule did not reveal the guided form"
    assert browser.evaluate("""
        const port = document.querySelector('#r-ports');
        return [...port.labels].some(label => label.textContent.includes('Destination port'))
            && port.getAttribute('aria-describedby') === 'r-ports-hint';
    """), "Guided port field lost its label or contextual hint"
    expect_text(browser, "65535", "#r-ports-hint")
    browser.fill("#r-sources", "192.0.2.0/24")
    browser.fill("#r-ports", "443")
    browser.fill("#r-desc", "Synthetic guided HTTPS")
    browser.fill("#top-summary", "M5 guided policy")
    browser.click(NAV + ' [data-policy-section="tab-nat"]')
    assert browser.visible("#tab-nat") and not browser.visible("#tab-filter")
    assert browser.visible(NAV + ' [data-policy-section="tab-nat"][aria-current="page"]')
    browser.key(RIGHT)
    focus_is_visible(browser, '[data-tab-target="tab-bridge"][aria-selected=true]')
    assert browser.visible("#tab-bridge")
    browser.click(NAV + ' [data-policy-section="tab-filter"]')
    assert browser.value("#r-sources") == "192.0.2.0/24"
    assert browser.value("#r-ports") == "443"
    assert browser.value("#r-desc") == "Synthetic guided HTTPS"
    assert browser.value("#top-summary") == "M5 guided policy"
    browser.click(submit("/manage/policies/rules/add"))
    expect_text(browser, "Synthetic guided HTTPS", "#tab-filter")
    assert browser.value("#top-summary") == "M5 guided policy", "Add Rule lost the revision note"
    assert revisions(state) == [], "Add Rule created a saved revision"

    browser.click('[data-tab-target="tab-json"]')
    assert browser.value("#raw-summary") == "M5 guided policy"
    browser.fill("#raw-summary", POLICY_NOTE)
    browser.click(NAV + ' [data-policy-section="tab-filter"]')
    state_form = '#tab-filter form[action="/manage/policies/rules/state"]:has(input[name="ruleIndex"][value="1"])'
    for enabled in (False, True):
        browser.click(state_form + " .enablement-switch")
        browser.evaluate("document.documentElement.dataset.fixturePendingSubmit = 'true';")
        browser.click(state_form + " button[type=submit]")
        browser.wait_for(lambda: browser.evaluate(
            "return document.readyState === 'complete' && !document.documentElement.dataset.fixturePendingSubmit;"
        ), "Expected a new document after updating rule state")
        assert browser.evaluate("return document.querySelector(arguments[0]).elements.enabled.checked;", state_form) == enabled
        assert browser.value("#top-summary") == POLICY_NOTE, "Updating rule state lost the latest revision note"
        assert not browser.evaluate("return !!document.querySelector('#revision-note-probe');"), "The revision note rendered as markup"
    assert revisions(state) == [], "Updating rule state created a saved revision"

    browser.click('form[action="/manage/policies/preview"] button:not([formaction])')
    browser.wait_for_path("/manage/policies/preview")
    assert browser.value("#top-summary") == POLICY_NOTE
    browser.click(NAV + ' [data-policy-section="tab-preview"]')
    assert browser.visible("#tab-preview"), "Review link did not show the preview"
    expect_text(browser, "Compiled nftables candidate", "#tab-preview")
    expect_text(browser, "192.0.2.0/24", "#tab-preview")
    assert revisions(state) == [], "Preview created a saved revision"
    assert rows(state, "SELECT * FROM audit_log") == audit_before, "Draft editing or preview wrote audit entries"
    capture("guided-review-light")
    browser.click('button[formaction="/manage/policies/save"]')
    browser.wait_for_path("/manage/policies")
    assert revisions(state) == [(1, POLICY_NOTE)], "Save did not persist the reviewed revision and note"
    browser.click(link("/manage"))
    expect_text(browser, "Connect a firewall host", "#next-action-heading")


def connect_host(browser, state, temp, capture):
    browser.click(link("/manage/hosts", ".next-action"))
    expect_text(browser, "already enrolled")
    expect_text(browser, "Registering a connection does not apply a policy")
    browser.select("#host-transport", "tls")
    assert browser.visible("#host-pin") and not browser.visible("#host-uid")
    browser.select("#host-transport", "unix")
    assert not browser.visible("#host-pin") and browser.visible("#host-uid")
    socket_path = temp / "no-listener.sock"
    assert not socket_path.exists()
    browser.fill("#host-name", "synthetic-browser-host")
    browser.fill("#host-endpoint", str(socket_path))
    browser.fill("#host-uid", str(os.getuid()))
    browser.click(submit("/manage/hosts/add"))
    expect_text(browser, "synthetic-browser-host")
    expect_text(browser, "unavailable")
    assert rows(state, "SELECT name, last_known_revision FROM hosts") == [("synthetic-browser-host", "0")]
    capture("saved-connection-light")


def import_policy(browser, state, capture):
    baseline = revisions(state)
    for fixture, name in (("unsupported.conf", "Unsupported logging"), ("supported.conf", "Supported HTTPS")):
        browser.click(link("/manage/sources"))
        browser.wait_for(lambda: browser.path() == "/manage/sources" and not browser.location().query,
                         "Expected the source library landing page")
        expect_text(browser, "Import nftables.conf")
        browser.fill("#source-name", name)
        browser.upload("#source-file", HERE / fixture)
        browser.click(submit("/manage/sources/import"))
        expect_text(browser, name, "#selected-source-heading")
        expect_text(browser, "Stored · not applied", "#selected-source-heading")
        browser.select("#conversion-role-0", "Filter")
        browser.click('button[name="operation"][value="review"]')
        expect_text(browser, "Saved conversion review")
        assert revisions(state) == baseline, "Upload or conversion review created a revision"
        if fixture == "unsupported.conf":
            expect_text(browser, "Blocking conversion gaps")
            expect_text(browser, "Line 4, column")
            assert not browser.visible(submit("/manage/sources/conversion/commit"))
            capture("blocked-import-light")
        else:
            expect_text(browser, "Ready to create a saved revision")
            assert browser.visible(submit("/manage/sources/conversion/commit"))
            capture("ready-import-light")
            browser.click(submit("/manage/sources/conversion/commit"))
            browser.wait_for_path("/manage/policies")
            assert len(revisions(state)) == len(baseline) + 1, "Commit did not create exactly one revision"
            browser.click(NAV + ' [data-policy-section="tab-preview"]')
            expect_text(browser, "198.51.100.0/24", "#tab-preview")
            capture("imported-revision-review-light")


def apply_surface(browser, state, capture, *, reader=False):
    before = rows(state, "SELECT * FROM hosts") + rows(state, "SELECT * FROM audit_log")
    browser.click(link("/manage/apply"))
    expect_text(browser, "Two-phase confirmed apply", "h1")
    expect_text(browser, "autonomous local watchdog rollback window")
    browser.click('form[action="/manage/apply"][method=get] button')
    expect_text(browser, "Live agent status")
    expect_text(browser, "synthetic-browser-host")
    expect_text(browser, "unavailable", "main .badge-danger")
    assert not browser.visible('form[action="/manage/apply/confirm"], form[action="/manage/apply/rollback"]')
    if reader:
        assert not browser.visible(APPLY_MUTATIONS), "Auditor saw apply mutation controls"
    else:
        assert browser.visible(START)
        assert browser.evaluate("""
            const form = document.querySelector(arguments[0]);
            const timeout = form.elements.confirmationTimeoutSeconds;
            return form.method === 'post' && form.elements.__RequestVerificationToken.value.length > 0
                && !!form.elements.hostId.value && timeout.required
                && timeout.min === '1' && timeout.max === '3600';
        """, START), "Start form lost host binding, CSRF token or timeout bounds"
        browser.select("#apply-revision", "1")
        assert browser.evaluate("return document.querySelector('#apply-revision').selectedOptions[0].text;").endswith(POLICY_NOTE)
    assert rows(state, "SELECT * FROM hosts") + rows(state, "SELECT * FROM audit_log") == before
    capture("auditor-apply-light" if reader else "administrator-apply-light")


def identity_settings(browser, capture):
    browser.click(link("/manage/settings"))
    browser.wait_for_path("/manage/settings")
    expect_text(browser, "System settings", "h1")
    browser.click('[data-tab-target="auth"]')
    expect_text(browser, "Local authentication")
    for path, heading in (
        ("/manage/identity/connection", "Identity provider connection"),
        ("/manage/identity/ldap", "LDAP connection"),
        ("/manage/identity/profiles", "OIDC profile defaults"),
        ("/manage/identity/mfa", "MFA policy"),
        ("/manage/identity/email-delivery", "Email delivery"),
        ("/manage/identity/mfa/recovery", "Authorize authenticator recovery"),
    ):
        browser.click(link(path, "main"))
        expect_text(browser, heading, "h1")
        browser.post("/back")
        browser.wait_for_path("/manage/settings")
        assert browser.visible('[data-tab-target="auth"][aria-selected=true]')
    capture("authentication-settings-light")

    browser.click(link("/manage/users"))
    expect_text(browser, "Local users", "h1")
    browser.click('details:has(form[action="/manage/users/create"]) > summary')
    browser.fill("#new-user-name", "fixture-auditor")
    browser.select("#new-user-role", "nergal:auditor")
    browser.fill("#new-user-password", PASSWORD)
    browser.click(submit("/manage/users/create"))
    expect_text(browser, "fixture-auditor")
    expect_text(browser, "User and profile activity")
    capture("local-users-light")
    browser.click(link("/profile"))
    expect_text(browser, "My profile", "h1")
    browser.fill("#profile-name", "Synthetic Console Administrator")
    browser.click(submit("/profile/save"))
    browser.wait_for(lambda: browser.value("#profile-name") == "Synthetic Console Administrator",
                     "Expected saved profile name")
    expect_text(browser, "Synthetic Console Administrator", ".topbar")
    capture("profile-light")


def desktop_dark(browser, capture):
    # Change the theme through the visible control and require computed styles to follow it.
    light = browser.evaluate("return getComputedStyle(document.body).backgroundColor;")
    browser.click('[data-theme-toggle][aria-label="Switch to dark theme"]')
    assert browser.visible('[data-theme-toggle][aria-label="Switch to light theme"]')
    dark = browser.evaluate("return getComputedStyle(document.body).backgroundColor;")
    assert light != dark, "Theme control did not change the rendered background"
    browser.click(link("/manage"))
    assert browser.evaluate("return document.documentElement.dataset.theme;") == "dark"
    expect_text(browser, "Pacific/Honolulu", NAV)
    assert browser.evaluate("""
        const instant = document.querySelector('time[data-local-time]');
        return instant.dateTime.endsWith('Z') && instant.textContent.includes('HST');
    """), "Overview timestamps lost UTC markup or browser-local Honolulu display"
    browser.key(TAB)
    focus_is_visible(browser, ".skip-link")
    capture("overview-dark")


def set_viewport(browser, *, mobile=False):
    width, height = (375, 812) if mobile else (1440, 1000)
    browser.cdp("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1, mobile=mobile)


def mobile_localization(browser, origin, temp, capture):
    set_viewport(browser, mobile=True)
    browser.post("/url", url=origin + "/manage/hosts")
    assert browser.evaluate("return window.innerWidth;") == 375
    browser.click(".language-menu > summary")
    browser.select("#ui-culture", "es-ES")
    browser.click(submit("/language"))
    browser.wait_for(lambda: browser.evaluate("return document.documentElement.lang;") == "es-ES",
                     "Expected the Hosts page in Spanish after language selection")
    browser.wait_for_path("/manage/hosts")
    expect_text(browser, "Equipos", "h1")
    expect_text(browser, "Registrar un equipo con agente")
    expect_text(browser, "Nombre del equipo", 'label[for="host-name"]')
    assert browser.evaluate("""
        return document.documentElement.scrollWidth <= document.documentElement.clientWidth;
    """), "Localized Hosts overflowed the 375px viewport"
    capture("hosts-mobile-es")

    browser.post("/url", url=origin + "/manage/sources")
    assert browser.evaluate("return document.documentElement.lang;") == "es-ES"
    expect_text(browser, "Biblioteca de fuentes nativas", ".appliance-content h1")
    assert not browser.evaluate("return document.querySelector('.appliance-content').hasAttribute('lang');")
    fixture = temp / "locale-include.conf"
    fixture.write_text('include "synthetic-include.nft"\n', encoding="utf-8")
    browser.fill("#source-name", "Synthetic include")
    browser.upload("#source-file", fixture)
    browser.click(submit("/manage/sources/import"))
    expect_text(browser, "Synthetic include", "#selected-source-heading")
    browser.click("[data-include-add]")
    assert browser.evaluate("""
        return [...document.querySelectorAll('.native-include-rows select')].map(select => select.ariaLabel);
    """) == ["synthetic-include.nft, archivo 1", "synthetic-include.nft, archivo 2"]
    browser.click('.native-include-row:last-child [data-include-move="up"]')
    assert browser.evaluate("""
        return document.querySelector('.native-include-row:first-child select').ariaLabel;
    """) == "synthetic-include.nft, archivo 1"
    capture("native-sources-mobile-es")
    set_viewport(browser)
    browser.post("/url", url=origin + "/manage/policies?section=json")
    browser.click('[data-tab-target="tab-json"]')
    expect_text(browser, "Aplicar sangría", ".code-editor-toolbar button")
    browser.click(".code-editor-toolbar button")
    expect_text(browser, "Se ha actualizado la sangría.", '.code-editor-toolbar [role="status"]')
    browser.post("/url", url=origin + "/manage/hosts")
    browser.click(".language-menu > summary")
    browser.select("#ui-culture", "en-US")
    browser.click(submit("/language"))
    browser.wait_for(lambda: browser.evaluate("return document.documentElement.lang;") == "en-US",
                     "Expected the Hosts page in source English after switching back")
    browser.wait_for_path("/manage/hosts")
    expect_text(browser, "Hosts", "h1")
    expect_text(browser, "Register agent host")
    expect_text(browser, "Host name", 'label[for="host-name"]')
    set_viewport(browser)


def right_to_left_navigation(browser, origin, capture):
    browser.post("/url", url=origin + "/manage/hosts")
    browser.click(".language-menu > summary")
    browser.select("#ui-culture", "ar")
    browser.click(submit("/language"))
    browser.wait_for(lambda: browser.evaluate("return document.documentElement.lang;") == "ar", "Expected Arabic")
    expect_text(browser, "تسجيل مضيف الوكيل", ".appliance-content")
    assert browser.evaluate("""
        const sidebar = document.querySelector('#management-navigation');
        const content = document.querySelector('.appliance-content');
        return document.documentElement.dir === 'rtl' && getComputedStyle(sidebar).direction === 'rtl'
            && getComputedStyle(content).direction === 'rtl'
            && sidebar.getBoundingClientRect().left >= content.getBoundingClientRect().right;
    """), "Arabic navigation or Hosts content did not follow right-to-left layout"
    capture("hosts-desktop-ar")

    browser.post("/url", url=origin + "/manage/policies?section=json")
    browser.click('[data-tab-target="tab-json"]')
    browser.wait_for(lambda: browser.visible(".cm-content"), "Expected the JSON editor in Arabic")
    assert browser.evaluate("""
        return document.documentElement.dir === 'rtl'
            && getComputedStyle(document.querySelector('.cm-content')).direction === 'ltr';
    """), "JSON punctuation and tokens must keep left-to-right order in Arabic"
    browser.post("/url", url=origin + "/manage/hosts")

    set_viewport(browser, mobile=True)
    toggle = "[data-sidebar-toggle]"
    browser.click(toggle)
    assert browser.visible(NAV)
    assert browser.evaluate("return document.documentElement.scrollWidth <= document.documentElement.clientWidth;")
    capture("navigation-mobile-ar")
    browser.key(ESCAPE)
    assert not browser.visible(NAV) and browser.visible(toggle + '[aria-expanded="false"]')
    browser.click(".language-menu > summary")
    browser.select("#ui-culture", "en-US")
    browser.click(submit("/language"))
    browser.wait_for(lambda: browser.evaluate("return document.documentElement.lang;") == "en-US", "Expected English")
    set_viewport(browser)


def mobile_and_sign_out(browser, origin, capture):
    set_viewport(browser, mobile=True)
    browser.cdp("Emulation.setTouchEmulationEnabled", enabled=True)
    browser.post("/url", url=origin + "/")
    assert browser.evaluate("return window.innerWidth;") == 375
    toggle = "[data-sidebar-toggle]"
    assert browser.visible(toggle) and not browser.visible(NAV)
    browser.key(TAB)
    focus_is_visible(browser, ".skip-link")
    browser.key(TAB)
    browser.key(TAB)
    focus_is_visible(browser, toggle)
    browser.key(ENTER)
    assert browser.visible(NAV) and browser.visible(toggle + '[aria-expanded="true"]')
    browser.key(ESCAPE)
    focus_is_visible(browser, toggle + '[aria-expanded="false"]')
    assert not browser.visible(NAV)
    capture("overview-mobile-dark")
    for page, name in (("/manage/policies?section=filter", "rules"), ("/manage/hosts", "hosts"),
                       ("/manage/sources", "import"), ("/manage/apply", "apply"),
                       ("/manage/settings", "settings"), ("/profile", "profile")):
        # Start at the top so the sticky header cannot cover the opened menu links.
        browser.evaluate("window.scrollTo({top: 0, behavior: 'instant'});")
        browser.click(toggle)
        selector = NAV + ' [data-policy-section="tab-filter"]' if name == "rules" else link(page)
        browser.click(selector)
        browser.wait_for_path(page.split("?")[0])
        assert browser.evaluate("""
            return document.documentElement.scrollWidth <= document.documentElement.clientWidth;
        """), f"Horizontal page overflow at {page} in the 375px viewport"
        capture(f"{name}-mobile-dark")
    set_viewport(browser)
    browser.cdp("Emulation.setTouchEmulationEnabled", enabled=False)
    browser.click('[data-theme-toggle][aria-label="Switch to light theme"]')
    browser.click(submit("/logout"))
    browser.wait_for_path("/login")


def read_only(browser, origin, state, capture):
    login(browser, "fixture-auditor")
    expect_text(browser, "Read-only administration", "#next-action-heading")
    assert not browser.visible(link("/manage/sources")) and not browser.visible(link("/manage/users"))
    apply_surface(browser, state, capture, reader=True)
    for path in ("/manage/sources", "/manage/users"):
        browser.post("/url", url=origin + path)
        assert browser.evaluate("return performance.getEntriesByType('navigation')[0].responseStatus;") == 403
    browser.post("/url", url=origin + "/profile")
    assert browser.value("#profile-name") != "Synthetic Console Administrator"


def tls_pin(certificate):
    public_key = subprocess.check_output(["openssl", "x509", "-in", certificate, "-pubkey", "-noout"])
    spki = subprocess.check_output(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public_key)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def main():
    if not __debug__:
        sys.exit("Run this harness without Python assertion optimization.")
    if len(sys.argv) > 1:
        sys.exit("Usage: python3 -B tests/integration/m5-usability/check.py")
    browser_bin = os.environ.get("CHROMIUM_BIN") or next(
        (path for name in ("chromium", "google-chrome", "google-chrome-stable") if (path := shutil.which(name))),
        None,
    )
    driver = os.environ.get("CHROMEDRIVER_BIN") or shutil.which("chromedriver")
    if not (browser_bin and driver and DLL.is_file() and ADMIN_TOOL.is_file()):
        sys.exit("Matching Chromium/Chrome and ChromeDriver and existing Release assemblies are required.")
    # The controller inherits the fixture's explicit settings, even from a shell configured for a shared sandbox.
    for name in set(os.environ) - {"PATH", "DOTNET_ROOT", "LANG", "LC_ALL", "TZ"}:
        del os.environ[name]
    os.umask(0o077)
    artifact_root = ROOT / "artifacts" / "m5-usability"
    artifact_root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=artifact_root))
    report = {
        "result": "failed",
        "assemblies": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in (DLL, ADMIN_TOOL)},
        "checks": {},
        "screenshots": [],
    }
    print(f"M5 usability artifacts: {output}", flush=True)
    stage = "fixture setup"
    try:
        with tempfile.TemporaryDirectory(prefix="nergal-m5-") as directory:
            temp = Path(directory)
            tls = provision(temp)
            state = temp / "controller-state"
            state.mkdir(mode=0o700)
            subprocess.run(["dotnet", ADMIN_TOOL, "controller", "init", state], check=True)
            settings = {
                # Build output resolves static assets through its development manifest.
                "ASPNETCORE_ENVIRONMENT": "Development",
                "ControllerState__Enabled": "true",
                "ControllerState__Directory": str(state),
            }
            with host(temp, tls, settings) as https, launch(driver, browser_bin, temp, tls_pin(temp / "tls.crt")) as browser:
                origin = f"https://127.0.0.1:{https.ports['https']}"
                report["browser"] = browser.version
                browser.cdp("Network.enable")
                browser.cdp("Network.setBlockedURLs", urls=[
                    f"{origin}/{scope}/apply/{operation}*"
                    for scope in ("manage", "controller")
                    for operation in ("start", "confirm", "rollback")
                ])
                set_viewport(browser)

                def capture(name):
                    filename = name + ".png"
                    browser.screenshot(output / filename)
                    report["screenshots"].append(filename)

                try:
                    for stage, check, args in (
                        ("first use and keyboard skip", first_use, (origin, state, capture)),
                        ("guided draft, review and save", create_policy, (state, capture)),
                        ("connection form and registration", connect_host, (state, temp, capture)),
                        ("blocked and supported source conversion", import_policy, (state, capture)),
                        ("administrator apply surface", apply_surface, (state, capture)),
                        ("identity and settings", identity_settings, (capture,)),
                        ("dark theme and browser-local time", desktop_dark, (capture,)),
                        ("Spanish Hosts, native sources, and JSON editor", mobile_localization, (origin, temp, capture)),
                        ("right-to-left navigation and Hosts content", right_to_left_navigation, (origin, capture)),
                        ("mobile navigation and sign-out", mobile_and_sign_out, (origin, capture)),
                        ("auditor navigation and denial", read_only, (origin, state, capture)),
                    ):
                        check(browser, *args)
                        report["checks"][stage] = "passed"
                        print(f"PASS {stage}", flush=True)
                except Exception:
                    try:
                        capture("failure")
                    except Exception as screenshot_error:
                        report["screenshot_error"] = type(screenshot_error).__name__
                    raise
                stage = "fixture shutdown"
        report["result"] = "passed"
    except Exception as error:
        diagnostic = str(error).replace(PASSWORD, "[fixture password]")
        report["checks"][stage] = "failed"
        frame = traceback.extract_tb(error.__traceback__)[-1]
        report["failure"] = {
            "stage": stage, "error": f"{type(error).__name__}: {diagnostic}",
            "location": f"{Path(frame.filename).name}:{frame.lineno}",
        }
        print(f"FAIL {stage} at {report['failure']['location']}: {report['failure']['error']}", file=sys.stderr)
    finally:
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return int(report["result"] != "passed")


if __name__ == "__main__":
    sys.exit(main())
