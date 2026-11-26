#!/usr/bin/env python3
"""Exercise Forgejo recipe attachment against a disposable HTTP endpoint."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
from threading import Thread
import unittest


aur = Path(__file__).resolve().parents[1] / "deploy" / "aur"


class RecipeAttachmentTests(unittest.TestCase):
    def test_attaches_once_and_refuses_a_different_or_unstable_release(self):
        tag = "2026.11.21.1"
        release = {"tag_name": tag, "draft": False, "prerelease": False, "assets": []}
        uploaded = []

        class ReleaseApi(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(release).encode())

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                uploaded.append((self.path, self.headers["Authorization"], body))
                release["assets"].append({"name": "nergal-aur-recipes.zip"})
                self.send_response(201)
                self.end_headers()

            def log_message(self, *_args):
                pass

        with tempfile.TemporaryDirectory() as directory, ThreadingHTTPServer(("127.0.0.1", 0), ReleaseApi) as api:
            worker = Thread(target=api.serve_forever, daemon=True)
            worker.start()
            bundle = Path(directory, "recipes.zip")
            bundle.write_bytes(b"test AUR bundle")
            environment = {
                **os.environ,
                "GITHUB_API_URL": f"http://127.0.0.1:{api.server_port}/api/v1",
                "GITHUB_REPOSITORY": "example/nergal",
                "AUR_RELEASE_ID": "42",
                "AUR_RELEASE_TAG": tag,
                "RELEASE_TOKEN": "test-credential",
                "NO_PROXY": "127.0.0.1",
            }
            command = ["bash", str(aur / "attach-recipes.sh"), str(bundle)]
            try:
                for modified in ({"tag_name": "v2026.12.1"}, {"prerelease": True}):
                    original = release.copy()
                    release.update(modified)
                    result = subprocess.run(command, env=environment, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Release changed or is no longer stable", result.stderr)
                    self.assertEqual(uploaded, [])
                    release.update(original)
                subprocess.run(command, env=environment, check=True, capture_output=True)
                subprocess.run(command, env=environment, check=True, capture_output=True)
            finally:
                api.shutdown()
                worker.join()

        self.assertEqual(len(uploaded), 1)
        path, authorization, body = uploaded[0]
        self.assertEqual(path, "/api/v1/repos/example/nergal/releases/42/assets?name=nergal-aur-recipes.zip")
        self.assertEqual(authorization, "token test-credential")
        self.assertIn(b"test AUR bundle", body)


if __name__ == "__main__":
    unittest.main()
