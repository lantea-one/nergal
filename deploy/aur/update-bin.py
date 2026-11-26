#!/usr/bin/env python3
"""Refresh nergal-bin from the latest stable, published Forgejo CalVer release."""

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import urlopen


PROJECT = "https://git.lantea.one/lantea-one/nergal"
CALVER = re.compile(r"v?(\d{4})\.([1-9]\d?)\.([1-9]\d?)(?:\.([1-9]\d*))?", re.ASCII)


def version_key(tag):
    """Order supported CalVer tags by their date and numeric revision."""
    match = CALVER.fullmatch(tag)
    if match is None:
        return None
    year, month, day = map(int, match.groups()[:3])
    try:
        return date(year, month, day), int(match[4] or 0)
    except ValueError:
        return None


def latest(releases):
    """Select the newest stable version, preferring v-prefixed tags on a tie."""
    candidates = []
    for release in releases:
        if release["draft"] or release["prerelease"]:
            continue
        tag = release["tag_name"]
        key = version_key(tag)
        if key is not None:
            candidates.append((key, tag))
    if not candidates:
        raise ValueError("No stable Nergal CalVer release is published")
    return max(candidates)[1]


def released_versions():
    """Read every release page so a recent backfill cannot roll back the recipe."""
    page = 1
    while True:
        url = "https://git.lantea.one/api/v1/repos/lantea-one/nergal/releases"
        with urlopen(f"{url}?limit=50&page={page}", timeout=30) as response:
            releases = json.load(response)
        if not releases:
            return
        yield from releases
        page += 1


def archive_digest(manifest, name):
    """Require one SHA-256 entry for the exact release archive."""
    matches = re.findall(rf"^([a-f0-9]{{64}}) [ *]{re.escape(name)}$", manifest, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"SHA256SUMS must list {name} exactly once")
    return matches[0]


def download_digest(url):
    with urlopen(url, timeout=120) as response:
        return hashlib.file_digest(response, "sha256").hexdigest()


def render(recipe, tag, archive_hash, license_hash):
    """Update release fields while retaining package layout and dependencies."""
    version = tag.removeprefix("v")
    if f"pkgver={version}\n" not in recipe:
        recipe = re.sub(r"^pkgrel=\d+$", "pkgrel=1", recipe, flags=re.MULTILINE)
    recipe = re.sub(r"^pkgver=.*$", f"pkgver={version}", recipe, flags=re.MULTILINE)
    recipe = re.sub(r"^_tag=.*$", f"_tag={tag}", recipe, flags=re.MULTILINE)
    return re.sub(
        r"^sha256sums=\([^)]*\)$",
        f"sha256sums=('{archive_hash}'\n            '{license_hash}')",
        recipe,
        flags=re.MULTILINE,
    )


def update(directory, tag):
    archive = f"nergal_{tag.removeprefix('v')}_linux-x64.tar.gz"
    downloads = f"{PROJECT}/releases/download/{tag}"
    with urlopen(f"{downloads}/SHA256SUMS", timeout=30) as response:
        expected = archive_digest(response.read().decode("ascii"), archive)
    if download_digest(f"{downloads}/{archive}") != expected:
        raise ValueError(f"Forgejo release archive {archive} failed SHA-256 verification")
    license_hash = download_digest(f"{PROJECT}/raw/tag/{tag}/LICENSE")
    package = directory / "PKGBUILD"
    proposed = render(package.read_text(), tag, expected, license_hash)
    with tempfile.TemporaryDirectory() as staged:
        Path(staged, "PKGBUILD").write_text(proposed)
        metadata = subprocess.check_output(["makepkg", "--printsrcinfo"], cwd=staged, text=True)
    package.write_text(proposed)
    (directory / ".SRCINFO").write_text(metadata)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "directory", type=Path, nargs="?", default=Path(__file__).resolve().parent / "nergal-bin",
        help="nergal-bin AUR checkout containing the PKGBUILD to update",
    )
    arguments = parser.parse_args()
    try:
        tag = latest(released_versions())
        update(arguments.directory, tag)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Cannot refresh nergal-bin: {error}\n")
    print(f"Prepared nergal-bin for Forgejo release {tag}")


if __name__ == "__main__":
    main()
