#!/usr/bin/env python3
"""Verify static Forgejo Pages documentation portal structure, links, and safety hygiene."""
import re
import sys
from pathlib import Path
from pages_assets import verify_shared_assets

ROOT = Path(__file__).resolve().parent.parent
PAGES = ROOT / "pages"

REQUIRED_FILES = [
    "oidc-connection.md",
    "oauth-connection.md",
    "overview-host-observations.md",
    "ui-localization.md",
    "controller-sqlite-backup.md",
    "controller-server-databases.md",
    "assets/screenshots/oidc-connection-dark.jpg",
    "assets/screenshots/oidc-connection-light.jpg",
    "assets/screenshots/oidc-connection-mobile.jpg",
    ".nojekyll",
    "index.html",
    "index.md",
    "_sidebar.md",
    "_navbar.md",
    "assets/nergal-theme.css",
    "assets/application.css",
    "brand/guardian.png",
    "brand/guardian.svg",
    "assets/theme.js",
    "assets/portal.js",
    "architecture.md",
    "policy-reference.md",
    "agent-and-protocol.md",
    "web-controller-and-rbac.md",
    "deployment-and-packaging.md",
    "testing-and-conformance.md",
    "release-notes.md",
    "router-migration-and-sandbox.md",
    "assets/screenshots/settings-dark.jpg",
    "assets/screenshots/settings-light.jpg",
    "assets/screenshots/policies-light.jpg",
    "assets/screenshots/policies-mobile.jpg",
    "assets/screenshots/editor-light.jpg",
    "assets/screenshots/editor-dark.jpg",
    "assets/screenshots/editor-mobile.jpg",
    "assets/screenshots/pages-light.jpg",
    "assets/screenshots/pages-dark.jpg",
    "assets/screenshots/pages-mobile.jpg",
    "assets/screenshots/auxiliary-readiness.jpg",
    "native-source-library.md",
    "assets/screenshots/source-structure-dark.jpg",
    "assets/screenshots/source-structure-mobile-light.jpg",
    "policy-exports.md",
    "assets/screenshots/policy-exports-dark.jpg",
    "assets/screenshots/policy-exports-mobile.jpg",
    "reusable-object-library.md",
    "native-static-lists.md",
    "assets/screenshots/native-static-sets-dark.jpg",
    "assets/screenshots/native-static-sets-light.jpg",
    "assets/screenshots/native-static-sets-mobile.jpg",
    "milestones.md",
    "rule-enabled-state.md",
    "guided-router-forms.md",
    "assets/screenshots/raw-prerouting-dark.jpg",
    "assets/screenshots/auxiliary-forms-dark.jpg",
    "assets/screenshots/auxiliary-references-dark.jpg",
    "assets/screenshots/transport-references-dark.jpg",
    "assets/screenshots/list-version-comparison-dark.jpg",
    "assets/screenshots/list-history-selector-dark.jpg",
    "assets/screenshots/postrouting-addresses-dark.jpg",
    "assets/screenshots/bridge-addresses-dark.jpg",
    "assets/screenshots/dnat-port-references-dark.jpg",
    "assets/screenshots/dnat-address-references-dark.jpg",
    "assets/screenshots/bridge-forms-dark.jpg",
    "assets/screenshots/bridge-forms-mobile.jpg",
    "assets/screenshots/mss-clamp-light.jpg",
    "assets/screenshots/router-conditions-dark.jpg",
    "assets/screenshots/router-postrouting-light.jpg",
    "assets/screenshots/router-postrouting-mobile.jpg",
    "assets/screenshots/rule-states-dark.jpg",
    "assets/screenshots/policy-objects-dark.jpg",
    "assets/screenshots/object-library-dark.jpg",
    "assets/screenshots/object-library-light.jpg",
    "assets/screenshots/object-library-mobile.jpg",
    "assets/screenshots/source-library-dark.jpg",
    "assets/screenshots/source-library-light.jpg",
    "assets/screenshots/source-library-mobile.jpg",
    "assets/screenshots/migration-review-dark.jpg",
    "assets/screenshots/migration-review-light.jpg",
    "assets/screenshots/migration-review-mobile.jpg",
    "assets/screenshots/native-conversion-dark.jpg",
    "assets/screenshots/native-conversion-light.jpg",
    "assets/screenshots/native-conversion-mobile.jpg",
    "assets/screenshots/native-conversion-blocked.jpg",
    "appliance-console.md",
    "local-users-and-profiles.md",
    "oidc-profile-defaults.md",
    "assets/screenshots/oidc-profile-mapping-dark.jpg",
    "assets/screenshots/oidc-profile-mapping-light.jpg",
    "assets/screenshots/oidc-profile-mapping-mobile.jpg",
    "assets/screenshots/m5-users-dark.jpg",
    "assets/screenshots/enablement-settings-dark.jpg",
    "assets/screenshots/rule-form-layout-dark.jpg",
    "assets/screenshots/rule-form-layout-mobile.jpg",
    "assets/screenshots/enablement-settings-light.jpg",
    "assets/screenshots/m5-users-light.jpg",
    "assets/screenshots/m5-profile-dark.jpg",
    "assets/screenshots/m5-profile-light.jpg",
    "assets/screenshots/m5-profile-mobile.jpg",
    "assets/screenshots/m5-navigation-mobile.jpg",
    "assets/screenshots/m5-error-dark.jpg",

    "assets/screenshots/console-overview-dark.jpg",
    "assets/screenshots/console-sign-in-light.jpg",
    "assets/screenshots/console-sign-in-dark.jpg",
    "assets/screenshots/console-sign-in-mobile.jpg",
    "assets/screenshots/console-rules-light.jpg",
    "assets/screenshots/console-mobile.jpg",
    "assets/screenshots/console-navigation-mobile.jpg",
]

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
FORBIDDEN_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"fwcloud", re.IGNORECASE),
]


def main() -> int:
    errors: list[str] = verify_shared_assets()

    if not PAGES.is_dir():
        print("ERROR: pages/ directory missing", file=sys.stderr)
        return 1

    for rel in REQUIRED_FILES:
        path = PAGES / rel
        if not path.is_file():
            errors.append(f"Missing required pages file: pages/{rel}")

    index_html = (PAGES / "index.html").read_text(encoding="utf-8") if (PAGES / "index.html").is_file() else ""
    if "assets/nergal-theme.css" not in index_html or "window.$docsify" not in index_html:
        errors.append("pages/index.html missing Docsify bootstrap or theme stylesheet")

    md_files = sorted(PAGES.rglob("*.md"))
    for md in md_files:
        text = md.read_text(encoding="utf-8")
        for pat in FORBIDDEN_PATTERNS:
            if pat.search(text):
                errors.append(f"Forbidden pattern {pat.pattern!r} matched in {md.relative_to(ROOT)}")

        for match in LINK_RE.finditer(text):
            target = match.group(1).strip()
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target_path = target.split("#", 1)[0].split("?", 1)[0]
            if not target_path:
                continue
            resolved = (md.parent / target_path).resolve()
            if not resolved.is_file() or PAGES.resolve() not in resolved.parents:
                errors.append(f"Broken internal link {target!r} in {md.relative_to(ROOT)}")

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print(f"PASS: verified {len(REQUIRED_FILES)} required pages files and {len(md_files)} markdown documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
