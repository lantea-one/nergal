"""Verify CalVer selection without Docker or a live registry."""

import io
import json
from pathlib import Path
import runpy
import unittest


release = runpy.run_path(str(Path(__file__).resolve().parents[1] / "deploy/container/release-version.py"))


class TagPages:
    def __init__(self, *pages):
        self.pages = iter(pages)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request.full_url)
        tags, link = next(self.pages)
        response = io.StringIO(json.dumps({"tags": tags}))
        response.headers = {"Link": link}
        return response


class ReleaseVersionTests(unittest.TestCase):
    def test_release_ref_must_match_the_project_version(self):
        version = release["project_version"]()
        for tag in (version, "v" + version):
            self.assertEqual(version, release["project_version"]("refs/tags/" + tag))
        for ref in ("refs/tags/2030.1.1-preview", "refs/tags/2030.1.1", "refs/heads/" + version,
                    "refs/tags/latest", "refs/tags/vv" + version):
            with self.assertRaises(ValueError):
                release["project_version"](ref)

    def test_backfills_and_incomplete_uploads_keep_the_newest_pair(self):
        controller = {"2026.9.30.10", "2026.10.1", "2026.10.1.2", "2026.10.1.10", "2026.11.1", "latest"}
        agent = {"2026.9.30.10", "2026.10.1", "2026.10.1.2", "2026.10.1.10", "latest", "2026.2.30"}
        self.assertEqual("2026.10.1.10", release["latest_complete"](controller, agent))
        with self.assertRaises(ValueError):
            release["latest_complete"]({"2026.11.1", "latest"}, {"2026.10.1", "latest"})

    def test_registry_continuation_stays_on_the_same_image_and_origin(self):
        server, name = "https://registry.example", "project/app/agent"
        pages = TagPages((["2026.9.30"], '</v2/project/app/agent/tags/list?n=100&last=2026.9.30>; rel="next"'),
                         (["2026.10.1"], None))
        self.assertEqual({"2026.9.30", "2026.10.1"}, release["registry_tags"](server, name, pages, "Basic fixture"))
        self.assertEqual(2, len(pages.requests))
        foreign = TagPages((["2026.9.30"], '<https://other.example/v2/project/app/agent/tags/list>; rel="next"'))
        with self.assertRaises(ValueError):
            release["registry_tags"](server, name, foreign, "Basic fixture")
        self.assertEqual(1, len(foreign.requests))


if __name__ == "__main__":
    unittest.main()
