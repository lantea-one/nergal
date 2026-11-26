#!/usr/bin/env python3
"""Exercise Forgejo release attachment against a disposable HTTP endpoint."""

from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit


aur = Path(__file__).resolve().parents[1] / "deploy" / "aur"
tag = "v2026.11.21.1"
archive_name = "nergal_2026.11.21.1_linux-x64.tar.gz"


class ReleaseAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.release = {"tag_name": tag, "draft": False, "prerelease": False}
        self.files = {}
        self.uploaded = []
        self.fail_once = None
        fixture = self

        class ReleaseApi(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api/v1/repos/example/nergal/releases/42":
                    data = json.dumps({
                        **fixture.release, "assets": [{"name": name} for name in fixture.files],
                    }).encode()
                elif self.path.startswith(f"/example/nergal/releases/download/{tag}/"):
                    data = fixture.files.get(self.path.rsplit("/", 1)[-1])
                else:
                    data = None
                if data is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                target = urlsplit(self.path)
                if target.path != "/api/v1/repos/example/nergal/releases/42/assets":
                    self.send_error(404)
                    return
                if self.headers["Authorization"] != "token test-credential":
                    self.send_error(401)
                    return
                name, = parse_qs(target.query)["name"]
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if fixture.fail_once == name:
                    fixture.fail_once = None
                    self.send_error(503)
                    return
                descriptor = f"Content-Type: {self.headers['Content-Type']}\r\n\r\n".encode()
                part, = BytesParser(policy=policy.default).parsebytes(descriptor + body).iter_parts()
                fixture.files[name] = part.get_payload(decode=True)
                fixture.uploaded.append(name)
                self.send_response(201)
                self.end_headers()

            def log_message(self, *_args):
                pass

        api = self.enterContext(ThreadingHTTPServer(("127.0.0.1", 0), ReleaseApi))
        worker = Thread(target=api.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(api.shutdown)
        server = f"http://127.0.0.1:{api.server_port}"
        self.environment = {
            **os.environ,
            "GITHUB_API_URL": f"{server}/api/v1",
            "GITHUB_SERVER_URL": server,
            "GITHUB_REPOSITORY": "example/nergal",
            "AUR_RELEASE_ID": "42",
            "AUR_RELEASE_TAG": tag,
            "RELEASE_TOKEN": "test-credential",
            "NO_PROXY": "127.0.0.1",
        }

    def attach(self, *names):
        paths = [self.directory / name for name in names]
        for file in paths:
            file.write_bytes(f"fixture for {file.name}".encode())
        return subprocess.run(
            ["bash", str(aur / "attach-release-assets.sh"), *paths],
            env=self.environment,
            capture_output=True,
            text=True,
        )

    def test_bundle_refuses_different_or_unstable_release_and_uploads_once(self):
        name = "nergal-aur-recipes.zip"
        for modified in ({"tag_name": "v2026.12.1"}, {"prerelease": True}):
            original = self.release.copy()
            self.release.update(modified)
            result = self.attach(name)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Release changed or is no longer stable", result.stderr)
            self.assertEqual(self.uploaded, [])
            self.release = original
        self.attach(name).check_returncode()
        self.attach(name).check_returncode()
        self.assertEqual(self.uploaded, [name])

    def test_archive_and_checksum_resume_after_interrupted_upload(self):
        self.fail_once = "SHA256SUMS"
        result = self.attach(archive_name, "SHA256SUMS")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.uploaded, [archive_name])
        self.attach(archive_name, "SHA256SUMS").check_returncode()
        self.attach(archive_name, "SHA256SUMS").check_returncode()
        self.assertEqual(self.uploaded, [archive_name, "SHA256SUMS"])
        self.assertEqual(self.files[archive_name], (self.directory / archive_name).read_bytes())
        self.assertEqual(self.files["SHA256SUMS"], (self.directory / "SHA256SUMS").read_bytes())

    def test_partial_set_with_different_content_does_not_publish_missing_asset(self):
        for existing, missing in ((archive_name, "SHA256SUMS"), ("SHA256SUMS", archive_name)):
            with self.subTest(existing=existing):
                self.files = {existing: b"different release bytes"}
                result = self.attach(archive_name, "SHA256SUMS")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"Existing asset {existing} differs", result.stderr)
                self.assertNotIn(missing, self.files)
                self.assertEqual(self.uploaded, [])


if __name__ == "__main__":
    unittest.main()
