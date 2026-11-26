#!/usr/bin/env python3
"""Collect offline notices for NuGet runtime packages in published apps."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import BadZipFile, ZipFile


LICENSE_TEXT_DIR = Path(__file__).with_name("nuget-license-texts")
LICENSE_TEXTS = {"MIT": "MIT.txt", "Apache-2.0": "Apache-2.0.txt", "PostgreSQL": "PostgreSQL.txt"}


class NoticeError(Exception):
    pass


def is_notice_file(entry: str) -> bool:
    """Recognize upstream license files and singular/plural third-party notices."""
    stem = Path(entry).name.rsplit(".", 1)[0]
    normalized = re.sub(r"[^a-z0-9]", "", stem.casefold())
    return (
        normalized.startswith(("license", "licence", "copying"))
        or normalized in {"notice", "notices", "thirdpartynotice", "thirdpartynotices"}
    )


def package_is_published(details: dict) -> bool:
    """Keep packages with neutral/Linux assets; omit Windows-only runtime targets."""
    if any(details.get(asset) for asset in ("runtime", "native", "resources")):
        return True
    runtime_targets = details.get("runtimeTargets") or {}
    if not runtime_targets:
        return False
    rids = [str(asset.get("rid", "")).casefold() for asset in runtime_targets.values()]
    # Missing RID metadata is ambiguous, so retain that package for review.
    return any(not rid.startswith("win") for rid in rids)


def package_root(name: str, version: str, roots: list[Path]) -> Path:
    for root in roots:
        candidate = root / name.lower() / version.lower()
        if candidate.is_dir():
            return candidate
    raise NoticeError(f"missing package in local cache: {name} {version}")


def expression_license_texts(expression: str, name: str, version: str) -> list[tuple[str, bytes]]:
    """Return reviewed texts for simple or compound SPDX license expressions."""
    identifiers = re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression)
    identifiers = [token for token in identifiers if token not in {"AND", "OR", "WITH"}]
    if not identifiers:
        raise NoticeError(f"cannot identify SPDX license in expression for {name} {version}: {expression}")
    results: list[tuple[str, bytes]] = []
    for identifier in dict.fromkeys(identifiers):
        filename = LICENSE_TEXTS.get(identifier)
        if not filename:
            raise NoticeError(f"no reviewed offline license text mapped for {identifier} ({name} {version})")
        path = LICENSE_TEXT_DIR / filename
        if not path.is_file():
            raise NoticeError(f"reviewed license text missing for {identifier}: {path}")
        results.append((f"reviewed/{filename}", path.read_bytes()))
    return results


def package_license(root: Path, name: str, version: str,
                    expected_hash: str | None) -> tuple[str, str, str, str, list[tuple[str, bytes, str]]]:
    nupkg = root / f"{name.lower()}.{version.lower()}.nupkg"
    if not nupkg.is_file():
        raise NoticeError(f"missing cached .nupkg for {name} {version}")
    if expected_hash:
        metadata_path = root / ".nupkg.metadata"
        if not metadata_path.is_file():
            raise NoticeError(f"missing NuGet restore verification metadata for {name} {version}")
        try:
            content_hash = json.loads(metadata_path.read_text(encoding="utf-8")).get("contentHash", "")
        except (json.JSONDecodeError, OSError) as exc:
            raise NoticeError(f"invalid NuGet restore verification metadata for {name} {version}: {exc}") from exc
        if content_hash.removeprefix("sha512-") != expected_hash.removeprefix("sha512-"):
            raise NoticeError(f"assets contentHash does not match NuGet verified contentHash for {name} {version}")

    try:
        archive = ZipFile(nupkg)
    except (BadZipFile, OSError) as exc:
        raise NoticeError(f"invalid cached NuGet archive for {name} {version}: {exc}") from exc
    with archive:
        names = archive.namelist()
        nuspecs = [entry for entry in names if "/" not in entry.rstrip("/") and entry.lower().endswith(".nuspec")]
        if len(nuspecs) != 1:
            raise NoticeError(f"expected one root nuspec in archive for {name} {version}; found {len(nuspecs)}")
        try:
            nuspec = ET.fromstring(archive.read(nuspecs[0]))
        except (ET.ParseError, KeyError) as exc:
            raise NoticeError(f"invalid nuspec in archive for {name} {version}: {exc}") from exc

        def read_entry(entry: str) -> bytes:
            path = Path(entry)
            if path.is_absolute() or ".." in path.parts:
                raise NoticeError(f"unsafe notice path in package archive for {name} {version}: {entry}")
            try:
                return archive.read(entry)
            except KeyError as exc:
                raise NoticeError(f"notice entry missing from package archive for {name} {version}: {entry}") from exc

        package_texts = [
            (entry, read_entry(entry), "package")
            for entry in sorted(set(names))
            if not entry.endswith("/") and is_notice_file(entry)
        ]
        license_node = next((node for node in nuspec.iter() if node.tag.rsplit("}", 1)[-1] == "license"), None)
        license_url_node = next((node for node in nuspec.iter() if node.tag.rsplit("}", 1)[-1] == "licenseUrl"), None)
        copyright_node = next((node for node in nuspec.iter() if node.tag.rsplit("}", 1)[-1] == "copyright"), None)
        repository_node = next((node for node in nuspec.iter() if node.tag.rsplit("}", 1)[-1] == "repository"), None)
        license_url = (license_url_node.text or "").strip() if license_url_node is not None else ""
        copyright_text = (copyright_node.text or "").strip() if copyright_node is not None else ""
        repository = ""
        if repository_node is not None:
            repository = "; ".join(
                f"{key}={repository_node.attrib[key]}"
                for key in ("type", "url", "commit", "branch")
                if repository_node.attrib.get(key)
            )

        if license_node is None:
            if not license_url:
                raise NoticeError(f"missing license metadata and licenseUrl for {name} {version}; manual review required")
            expression = "UNCLASSIFIED: legacy licenseUrl only; manual review required"
            kind, license_value = "", ""
        else:
            kind = license_node.attrib.get("type", "").lower()
            license_value = (license_node.text or "").strip()
            if kind == "expression" and license_value:
                expression = license_value
            elif kind == "file" and license_value:
                expression = "(license file; see bundled text)"
            else:
                raise NoticeError(f"unsupported or empty license metadata for {name} {version}; manual review required")

        if kind == "file":
            declared = license_value.replace("\\", "/")
            if declared not in names:
                raise NoticeError(f"declared license file missing from package archive for {name} {version}: {license_value}")
            if all(entry != declared for entry, _, _ in package_texts):
                package_texts.append((declared, read_entry(declared), "package"))

    # For SPDX packages, retain package notices and include reviewed complete
    # license text when the package itself did not ship a license/copying file.
    has_license_text = any(
        re.sub(r"[^a-z0-9]", "", Path(entry).name.casefold()).startswith(("license", "licence", "copying"))
        for entry, _, _ in package_texts
    )
    if kind == "expression" and not has_license_text:
        package_texts.extend((path, data, "reviewed") for path, data in expression_license_texts(license_value, name, version))
    return expression, license_url, copyright_text, repository, sorted(package_texts, key=lambda item: (item[0], item[2]))


def collect(asset_paths: list[Path], output: Path, extra_package_roots: list[Path]) -> None:
    if output.exists() and any(output.iterdir()):
        raise NoticeError(f"output directory must be empty: {output}")
    packages: dict[tuple[str, str], tuple[str | None, bool]] = {}
    roots = list(extra_package_roots)
    for asset_path in asset_paths:
        data = json.loads(asset_path.read_text(encoding="utf-8"))
        roots.extend(Path(folder) for folder in data.get("packageFolders", {}))
        targets = data.get("targets", {})
        if not targets:
            raise NoticeError(f"no targets in assets file: {asset_path}")
        for target in targets.values():
            for key, details in target.items():
                if details.get("type") != "package":
                    continue
                name, _, version = key.rpartition("/")
                library = data.get("libraries", {}).get(key, {})
                if not name or not version:
                    raise NoticeError(f"invalid package identity in {asset_path}: {key}")
                identity = (name, version)
                expected_hash = library.get("sha512")
                previous_hash, was_published = packages.get(identity, (expected_hash, False))
                packages[identity] = (previous_hash, was_published or package_is_published(details))
    roots = list(dict.fromkeys(root.resolve() for root in roots))
    if not packages:
        raise NoticeError("no NuGet runtime packages found in supplied assets")

    records = []
    problems = []
    for (name, version), (expected_hash, published) in sorted(packages.items(), key=lambda item: (item[0][0].casefold(), item[0][1])):
        if not published:
            continue
        try:
            root = package_root(name, version, roots)
            metadata = package_license(root, name, version, expected_hash)
            records.append((name, version, *metadata))
        except NoticeError as exc:
            problems.append(str(exc))
    if problems:
        raise NoticeError("\n".join(problems))

    output.mkdir(parents=True, exist_ok=True)
    lines = ["# Third-party NuGet notices", "", "Generated from supplied runtime asset graphs and NuGet-verified local package archives.", ""]
    for name, version, expression, license_url, copyright_text, repository, files in records:
        lines += [f"## {name} {version}", "", f"License: {expression}"]
        if license_url:
            lines.append(f"NuGet license URL metadata (not fetched): {license_url}")
        if copyright_text:
            lines.append(f"Copyright: {copyright_text}")
        if repository:
            lines.append(f"Repository metadata: {repository}")
        if not files:
            lines.append("Upstream license/notice text: none included; manual review required.")
        else:
            for relative, contents, source_kind in files:
                safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{name}-{version}-{relative.replace('/', '-')}")
                target = output / "licenses" / safe
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
                lines.append(f"- licenses/{safe} ({source_kind})")
        lines.append("")
    (output / "THIRD-PARTY-NOTICES.txt").write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", action="append", type=Path, required=True, help="project.assets.json; repeat for each shipped application")
    parser.add_argument("--output", type=Path, required=True, help="empty output directory for inventory and copied texts")
    parser.add_argument("--package-cache", action="append", type=Path, default=[], help="additional local NuGet package cache root")
    args = parser.parse_args()
    try:
        for path in args.assets:
            if not path.is_file():
                raise NoticeError(f"assets file not found: {path}")
        collect(args.assets, args.output, args.package_cache)
    except (NoticeError, OSError, json.JSONDecodeError) as exc:
        print(f"notice collection failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
