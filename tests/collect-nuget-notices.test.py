#!/usr/bin/env python3
"""Focused offline tests for collect-nuget-notices.py."""

import base64
import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect-nuget-notices.py"
spec = importlib.util.spec_from_file_location("collect_nuget_notices", SCRIPT)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class NoticeCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cache = self.root / "packages"
        self.out = self.root / "out"

    def tearDown(self):
        self.temp.cleanup()

    def make_package(self, name="Example.Package", version="1.2.3", nuspec=None, license_text="Example license text", third_party=None):
        package = self.cache / name.lower() / version.lower()
        package.mkdir(parents=True)
        nuspec = nuspec or f'''<package><metadata><id>{name}</id><version>{version}</version><copyright>Copyright exact example 2026</copyright><repository type="git" url="https://example.invalid/repo" commit="0123456789abcdef"/><license type="expression">MIT</license><licenseUrl>https://licenses.nuget.org/MIT</licenseUrl></metadata></package>'''
        (package / f"{name.lower()}.nuspec").write_text(nuspec, encoding="utf-8")
        (package / "LICENSE.txt").write_text(license_text, encoding="utf-8")
        nupkg = package / f"{name.lower()}.{version.lower()}.nupkg"
        with zipfile.ZipFile(nupkg, "w") as archive:
            archive.writestr("package.nuspec", nuspec)
            if license_text:
                archive.writestr("LICENSE.txt", license_text)
            if third_party is not None:
                archive.writestr("THIRD-PARTY-NOTICES.TXT", third_party)
        # Model a signed NuGet package: restored contentHash describes the
        # package content before the signature block changes archive bytes.
        sha = base64.b64encode(hashlib.sha512(nupkg.read_bytes()).digest()).decode("ascii")
        with zipfile.ZipFile(nupkg, "a") as archive:
            archive.writestr(".signature.p7s", b"synthetic signature block")
        raw_hash = base64.b64encode(hashlib.sha512(nupkg.read_bytes()).digest()).decode("ascii")
        self.assertNotEqual(sha, raw_hash)
        (package / ".nupkg.metadata").write_text(json.dumps({"contentHash": sha}), encoding="utf-8")
        # The raw archive sidecar differs; assets match NuGet's restored content identity.
        (package / f"{name.lower()}.{version.lower()}.nupkg.sha512").write_text(raw_hash, encoding="utf-8")
        return package, sha

    def make_assets(self, sha, name="Example.Package", version="1.2.3", filename="project.assets.json"):
        path = self.root / filename
        key = f"{name}/{version}"
        data = {
            "packageFolders": {str(self.cache) + "/": {}},
            "libraries": {key: {"type": "package", "sha512": sha}},
            "targets": {"net10.0": {key: {"type": "package", "compile": {"lib/net10.0/a.dll": {}}, "runtime": {"lib/net10.0/a.dll": {}}}}},
        }
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_copies_upstream_license_and_generates_stable_deduplicated_inventory(self):
        _, sha = self.make_package()
        first = self.make_assets(sha)
        second = self.make_assets(sha, filename="second.assets.json")
        collector.collect([first, second], self.out, [])
        inventory = (self.out / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
        self.assertEqual(inventory.count("## Example.Package 1.2.3"), 1)
        self.assertIn("License: MIT", inventory)
        self.assertIn("NuGet license URL metadata (not fetched): https://licenses.nuget.org/MIT", inventory)
        self.assertIn("Copyright: Copyright exact example 2026", inventory)
        self.assertIn("Repository metadata: type=git; url=https://example.invalid/repo; commit=0123456789abcdef", inventory)
        files = list((self.out / "licenses").iterdir())
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_text(encoding="utf-8"), "Example license text")
        before = inventory
        self.out2 = self.root / "out2"
        collector.collect([second, first], self.out2, [])
        self.assertEqual(before, (self.out2 / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8"))

    def test_collects_third_party_notices_and_uses_reviewed_expression_fallback(self):
        _, sha = self.make_package(license_text="", third_party="Embedded upstream notice")
        assets = self.make_assets(sha)
        collector.collect([assets], self.out, [])
        inventory = (self.out / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
        copies = {path.name: path.read_text(encoding="utf-8") for path in (self.out / "licenses").iterdir()}
        self.assertTrue(any(name.endswith("THIRD-PARTY-NOTICES.TXT") for name in copies))
        self.assertIn("Embedded upstream notice", copies[next(name for name in copies if name.endswith("THIRD-PARTY-NOTICES.TXT"))])
        self.assertIn("licenses/Example.Package-1.2.3-reviewed-MIT.txt", inventory)
        self.assertIn("MIT License", (self.out / "licenses" / next(name for name in copies if name.endswith("reviewed-MIT.txt"))).read_text(encoding="utf-8"))

    def test_unmapped_spdx_expression_fails_closed_without_package_license_text(self):
        nuspec = '<package><metadata><id>Example.Package</id><version>1.2.3</version><license type="expression">BSD-3-Clause</license></metadata></package>'
        _, sha = self.make_package(nuspec=nuspec, license_text="")
        assets = self.make_assets(sha)
        with self.assertRaisesRegex(collector.NoticeError, "no reviewed offline license text mapped"):
            collector.collect([assets], self.out, [])

    def test_ignores_windows_only_runtime_target_but_keeps_linux_and_neutral_packages(self):
        windows_only = {
            "type": "package",
            "runtimeTargets": {
                "runtimes/win-x64/native/Microsoft.Data.SqlClient.SNI.dll": {"assetType": "native", "rid": "win-x64"},
                "runtimes/win-x86/native/Microsoft.Data.SqlClient.SNI.dll": {"assetType": "native", "rid": "win-x86"},
            },
        }
        self.assertFalse(collector.package_is_published(windows_only))
        self.assertTrue(collector.package_is_published({"type": "package", "runtime": {"lib/net10.0/a.dll": {}}}))
        self.assertTrue(collector.package_is_published({
            "type": "package",
            "runtimeTargets": {"runtimes/linux-x64/native/libexample.so": {"assetType": "native", "rid": "linux-x64"}},
        }))

        _, sha = self.make_package()
        assets = self.make_assets(sha)
        data = json.loads(assets.read_text(encoding="utf-8"))
        key = "Microsoft.Data.SqlClient.SNI.runtime/7.1.2"
        data["libraries"][key] = {"type": "package", "sha512": "unused-windows-package"}
        data["targets"]["net10.0"][key] = windows_only
        assets.write_text(json.dumps(data), encoding="utf-8")
        collector.collect([assets], self.out, [])
        inventory = (self.out / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
        self.assertNotIn("Microsoft.Data.SqlClient.SNI.runtime", inventory)
        self.assertIn("## Example.Package 1.2.3", inventory)

    def test_legacy_license_url_is_reported_for_manual_review(self):
        nuspec = '<package><metadata><id>Example.Package</id><version>1.2.3</version><licenseUrl>https://example.invalid/license</licenseUrl></metadata></package>'
        _, sha = self.make_package(nuspec=nuspec)
        assets = self.make_assets(sha)
        collector.collect([assets], self.out, [])
        inventory = (self.out / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
        self.assertIn("UNCLASSIFIED: legacy licenseUrl only; manual review required", inventory)
        self.assertIn("https://example.invalid/license", inventory)

    def test_rejects_hash_mismatch(self):
        self.make_package()
        assets = self.make_assets("wrong-hash")
        with self.assertRaisesRegex(collector.NoticeError, "assets contentHash does not match"):
            collector.collect([assets], self.out, [])

    def test_rejects_package_without_license_or_license_url_metadata(self):
        nuspec = '<package><metadata><id>Example.Package</id><version>1.2.3</version></metadata></package>'
        _, sha = self.make_package(nuspec=nuspec)
        assets = self.make_assets(sha)
        with self.assertRaisesRegex(collector.NoticeError, "missing license metadata"):
            collector.collect([assets], self.out, [])

    def test_requires_empty_output_directory(self):
        _, sha = self.make_package()
        assets = self.make_assets(sha)
        self.out.mkdir()
        (self.out / "existing").touch()
        with self.assertRaisesRegex(collector.NoticeError, "must be empty"):
            collector.collect([assets], self.out, [])


if __name__ == "__main__":
    unittest.main()
