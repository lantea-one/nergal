#!/usr/bin/env python3
"""Check stable release selection and the AUR recipe's pinned checksum contract."""

from pathlib import Path
import runpy
import unittest


aur = Path(__file__).resolve().parents[1] / "deploy" / "aur"
updater = runpy.run_path(str(aur / "update-bin.py"))


class AurReleaseTests(unittest.TestCase):
    def test_selects_latest_stable_calver_across_backfills(self):
        releases = [
            {"tag_name": tag, "draft": draft, "prerelease": prerelease}
            for tag, draft, prerelease in [
                ("v2026.11.21.10", False, False),
                ("v2026.11.21.2", False, False),
                ("2026.9.1", False, False),
                ("2027.1.1", False, True),
                ("2027.2.1", True, False),
                ("2027.2.31", False, False),
            ]
        ]
        self.assertEqual(updater["latest"](releases), "v2026.11.21.10")
        with self.assertRaisesRegex(ValueError, "No stable"):
            updater["latest"](releases[3:])

    def test_release_event_keeps_its_own_tag_when_a_newer_release_exists(self):
        old = {"tag_name": "2026.11.21.1", "draft": False, "prerelease": False}
        new = {**old, "tag_name": "v2026.12.1"}
        self.assertEqual(updater["select_release"]([new, old]), new["tag_name"])
        self.assertEqual(updater["select_release"]([new, old], old["tag_name"]), old["tag_name"])
        for unavailable in ([new], [{**old, "draft": True}], [{**old, "prerelease": True}]):
            with self.subTest(releases=unavailable), self.assertRaisesRegex(ValueError, "published stable"):
                updater["select_release"](unavailable, old["tag_name"])

    def test_requires_one_checksum_for_the_exact_archive(self):
        name = "nergal_2026.11.21.10_linux-x64.tar.gz"
        expected = "a" * 64
        exact = f"{expected}  {name}\n"
        incidental = f"{'b' * 64}  {name}.other\n"
        self.assertEqual(updater["archive_digest"](incidental + exact, name), expected)
        for invalid in (incidental, exact + exact, f"bad  {name}\n"):
            with self.subTest(manifest=invalid), self.assertRaisesRegex(ValueError, "exactly once"):
                updater["archive_digest"](invalid, name)

    def test_recipe_pins_tag_and_digests_and_resets_pkgrel_on_upgrade(self):
        old = (aur / "nergal-bin" / "PKGBUILD").read_text().replace("pkgrel=1", "pkgrel=3")
        self.assertIn("pkgrel=3", updater["render"](old, "2026.11.21.1", "a" * 64, "b" * 64))
        new = updater["render"](old, "v2026.11.21.10", "a" * 64, "b" * 64)
        for entry in ("pkgver=2026.11.21.10", "pkgrel=1", "_tag=v2026.11.21.10", "a" * 64, "b" * 64):
            self.assertIn(entry, new)
        self.assertNotIn("SKIP", new)


if __name__ == "__main__":
    unittest.main()
