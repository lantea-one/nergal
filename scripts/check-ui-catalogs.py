#!/usr/bin/env python3
"""Verify console resource structure and report missing translations."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/Nergal.Web"
SOURCE_LOCALE = "en-US"
CULTURE = re.compile(r'CultureInfo\.GetCultureInfo\("([A-Za-z]+(?:-[A-Za-z]+)?)"\)')
LOOKUP = re.compile(r'\b(?:L|localizer|strings)\??\[\s*("(?:[^"\\]|\\.)*")')
PLACEHOLDER = re.compile(r"(?<!\{)\{[0-9]+(?:[, :][^{}]+)?\}(?!\})|(?<!\$)\$(?!\$)")


def placeholders(message):
    return Counter(PLACEHOLDER.findall(message))


def load_catalog(path):
    entries = {}
    folded = set()
    for element in ET.parse(path).getroot().findall("data"):
        key = element.get("name", "")
        value = element.find("value")
        text = value.text if value is not None and len(value) == 0 else None
        if not key.strip() or key.casefold() in folded or not text or not text.strip():
            raise ValueError(f"{path.name}: invalid, empty or duplicate resource {key!r}")
        if placeholders(key) != placeholders(text):
            raise ValueError(f"{path.name}: placeholders differ for {key!r}")
        folded.add(key.casefold())
        entries[key] = text
    return entries


def literal_lookups():
    files = list(WEB.glob("*.cs"))
    for name, suffix in (("Views", "*.cshtml"), ("Components", "*.razor"), ("Controllers", "*.cs")):
        files.extend((WEB / name).rglob(suffix))
    for path in files:
        for match in LOOKUP.finditer(path.read_text(encoding="utf-8")):
            yield json.loads(match.group(1))


def inventory():
    locales = set(CULTURE.findall((WEB / "UiLocalization.cs").read_text(encoding="utf-8"))) - {SOURCE_LOCALE}
    root = WEB / "Resources"
    catalogs = {path.stem.removeprefix("UiStrings."): load_catalog(path)
                for path in sorted(root.glob("UiStrings.*.resx"))}
    if locales != catalogs.keys():
        raise ValueError(f"Locale registry and catalogs differ: {sorted(locales ^ catalogs.keys())}")
    # Include dynamic messages that use a catalog key selected by the view model.
    keys = set(literal_lookups()).union(*(catalog.keys() for catalog in catalogs.values()))
    normalized = {}
    for key in sorted(keys):
        previous = normalized.setdefault(key.casefold(), key)
        if previous != key:
            raise ValueError(f"Console lookup keys differ only by case: {previous!r} and {key!r}")
    return catalogs, keys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-complete", action="store_true", help="fail if any deployed locale is missing a message")
    parser.add_argument("--json", action="store_true", help="emit the exact missing messages by locale")
    args = parser.parse_args()

    try:
        catalogs, keys = inventory()
    except (OSError, ET.ParseError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1

    missing = {locale: sorted(keys - catalog.keys()) for locale, catalog in catalogs.items()}
    if args.json:
        print(json.dumps({"sourceMessages": len(keys), "missing": missing}, ensure_ascii=False, indent=2))
    else:
        print(f"{len(keys)} source messages across {len(catalogs)} translation catalogs")
        for locale, messages in missing.items():
            print(f"{locale}: {len(keys) - len(messages)}/{len(keys)} translated, {len(messages)} missing")
    return 1 if args.require_complete and any(missing.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
