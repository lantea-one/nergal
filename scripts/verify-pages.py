#!/usr/bin/env python3
"""Verify static Forgejo Pages documentation portal structure, links, and safety hygiene."""
import re
import sys
from pathlib import Path
from pages_assets import verify_shared_assets

ROOT = Path(__file__).resolve().parent.parent
PAGES = ROOT / "pages"

REQUIRED_FILES = [
    ".nojekyll",
    "index.html",
    "index.md",
    "_sidebar.md",
    "_navbar.md",
    "assets/nergal-theme.css",
    "assets/application.css",
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
    "assets/screenshots/migration-review-dark.jpg",
    "assets/screenshots/migration-review-light.jpg",
    "assets/screenshots/migration-review-mobile.jpg",
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
