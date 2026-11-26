"""Exercise a disposable Compose controller over certificate-verified loopback HTTPS."""

import json
import os
from pathlib import Path
import runpy
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[3]
SESSION_FIXTURES = ROOT / "tests/integration/local-sessions"
sys.path.insert(0, str(SESSION_FIXTURES))
import check as sessions

settings = runpy.run_path(str(SESSION_FIXTURES / "check-settings.py"))
OWNER = "1654:1654"
ACCOUNT_DIR = "/var/lib/nergal/state/accounts"
CONTROLLER_DIR = "/var/lib/nergal/state/controller"
KEY_DIR = "/var/lib/nergal/keyring/keys"
CERT_DIR = "/etc/nergal/credentials"


def make_credentials(root):
    credentials = root / "credentials"
    credentials.mkdir(mode=0o700)
    for name in ("https", "wrapping"):
        target = credentials if name == "https" else root
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
                        "-days", "2", "-subj", f"/CN=nergal-container-{name}",
                        "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", target / f"{name}.key", "-out", target / f"{name}.crt"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    subprocess.run(["openssl", "pkcs12", "-export", "-inkey", root / "wrapping.key",
                    "-in", root / "wrapping.crt", "-out", credentials / "wrapping.pfx",
                    "-passout", "pass:"], check=True, timeout=20)
    for file in credentials.iterdir():
        file.chmod(0o600)
    return credentials, ssl.create_default_context(cafile=str(credentials / "https.crt"))


class Deployment:
    def __init__(self, root, credentials):
        self.project = f"nergal-container-test-{uuid4().hex[:12]}"
        self.image = f"{self.project}:fixture"
        # Keep local Compose config and Buildx client writes outside the source tree.
        config = root / "docker"
        config.mkdir(mode=0o700)
        docker_env = {key: value for key, value in os.environ.items() if key != "DOCKER_CONTEXT"}
        if not docker_env.get("DOCKER_HOST", "unix:///var/run/docker.sock").startswith("unix:///"):
            raise RuntimeError("The fixture requires a local Docker Unix socket")
        self.env = {**docker_env, "DOCKER_CONFIG": str(config),
                    "NERGAL_IMAGE": self.image, "NERGAL_HTTPS_PORT": "0",
                    "NERGAL_CREDENTIALS_DIR": str(credentials),
                    "NERGAL_SETTINGS_FILE": str(root / "controller.env")}
        (root / "controller.env").write_text("AllowedHosts=127.0.0.1\n")
        self.compose_args = ["compose", "--project-name", self.project, "--env-file", "/dev/null",
                             "--file", str(ROOT / "docker-compose.yml")]

    def docker(self, *args, **kwargs):
        return subprocess.run(["docker", *args], cwd=ROOT, env=self.env, check=kwargs.pop("check", True),
                              timeout=kwargs.pop("timeout", 60), text=True, **kwargs)

    def compose(self, *args, **kwargs):
        return self.docker(*self.compose_args, *args, **kwargs)

    def admin(self, *args, **kwargs):
        return self.compose("run", "--rm", "--no-deps", "-T", "admin", *args, **kwargs)

    def exec(self, *args):
        return self.compose("exec", "-T", "controller", *args, capture_output=True).stdout.strip()

    def own_credentials(self, credentials, owner):
        # This helper can change ownership only on the disposable credential
        # bind. The application and admin containers both drop all capabilities.
        self.docker("run", "--rm", "--network", "none", "--read-only", "--user", "0:0",
                    "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
                    "--security-opt", "no-new-privileges", "--entrypoint", "/bin/chown",
                    "--mount", f"type=bind,src={credentials},dst=/fixture",
                    self.image, "-R", owner, "/fixture")

    def ready(self, tls):
        binding = self.compose("port", "controller", "8443", capture_output=True).stdout.strip()
        host, port = binding.split(":")
        assert host == "127.0.0.1" and 1 <= int(port) <= 65535, binding
        url = f"https://{binding}/healthz"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with urlopen(url, context=tls, timeout=2) as response:
                    assert response.status == 200 and response.read() == b"Healthy"
                return sessions.Browser({"https": int(port)}, tls)
            except URLError as error:
                if isinstance(error.reason, ssl.SSLCertVerificationError):
                    raise
                time.sleep(0.2)
        raise AssertionError("HTTPS health endpoint did not become ready")


def check_isolation(deployment):
    container = deployment.compose("ps", "-q", "controller", capture_output=True).stdout.strip()
    inspect = json.loads(deployment.docker("inspect", container, capture_output=True).stdout)[0]
    host = inspect["HostConfig"]
    assert inspect["Config"]["User"] == OWNER
    assert host["ReadonlyRootfs"] and not host["Privileged"] and not host["CapAdd"]
    assert host["CapDrop"] == ["ALL"] and "no-new-privileges:true" in host["SecurityOpt"]
    mounts = {mount["Destination"]: (mount["Type"], mount["RW"]) for mount in inspect["Mounts"]}
    assert mounts == {"/var/lib/nergal/state": ("volume", True),
                      "/var/lib/nergal/keyring": ("volume", True), CERT_DIR: ("bind", False)}

    process = dict(line.split(":", 1) for line in deployment.exec("cat", "/proc/1/status").splitlines())
    for ids in ("Uid", "Gid"):
        assert process[ids].split() == ["1654"] * 4
    for capset in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(process[capset], 16) == 0, capset
    assert process["NoNewPrivs"].strip() == "1"
    assert process["Umask"].strip() == "0077"
    mount_options = {entry[4]: set(entry[5].split(",")) for entry in
                     map(str.split, deployment.exec("cat", "/proc/1/mountinfo").splitlines())}
    assert "ro" in mount_options["/"]
    assert {"rw", "nosuid", "nodev", "noexec"} <= mount_options["/tmp"]
    paths = deployment.exec("stat", "-c", "%a %u:%g", ACCOUNT_DIR, CONTROLLER_DIR, KEY_DIR,
                            f"{ACCOUNT_DIR}/accounts.db", f"{CONTROLLER_DIR}/controller.db")
    assert paths.splitlines() == [f"700 {OWNER}"] * 3 + [f"600 {OWNER}"] * 2
    deployment.exec("sh", "-ec", "test ! -e /var/run/docker.sock; ! command -v nft; "
                    "test ! -e /opt/nergal/agent")


def check_controller(deployment, tls):
    deployment.admin("account", "init", ACCOUNT_DIR)
    deployment.admin("controller", "init", CONTROLLER_DIR)
    deployment.admin("account", "provision", ACCOUNT_DIR, "fixture-admin", "--password-stdin",
                     input=sessions.PASSWORD + "\n")
    duplicate = deployment.admin("controller", "init", CONTROLLER_DIR, check=False, capture_output=True)
    assert duplicate.returncode == 1, "Existing controller database must not be reinitialized"

    deployment.compose("up", "-d", "--no-build", "controller")
    browser = deployment.ready(tls)
    check_isolation(deployment)
    browser.request(settings["SETTINGS"], 401)
    browser.request("/healthz", 400, headers={"Host": "unexpected.example.invalid"})
    browser.request("/css/nergal.css", 200)
    try:
        urlopen(f"https://127.0.0.1:{browser.ports['https']}/healthz",
                context=ssl.create_default_context(), timeout=3).close()
    except URLError as error:
        assert isinstance(error.reason, ssl.SSLCertVerificationError)
    else:
        raise AssertionError("The fixture certificate must require explicit trust")

    browser.login()
    fields = settings["settings_fields"](browser)
    edit = {**fields, "applicationName": "Container Fixture"}
    settings["post"](browser, {k: v for k, v in edit.items() if k != settings["CSRF"]}, 400)
    denied = settings["settings_fields"](browser)
    assert (denied["applicationName"], denied[settings["TOKEN"]]) == (
        fields["applicationName"], fields[settings["TOKEN"]])
    settings["post"](browser, edit, 302)
    saved = settings["settings_fields"](browser)
    assert saved["applicationName"] == edit["applicationName"]
    assert saved[settings["TOKEN"]] != fields[settings["TOKEN"]]

    for change in (("restart", "controller"), ("up", "-d", "--no-build", "--force-recreate", "controller")):
        deployment.compose(*change)
        resumed = deployment.ready(tls)
        resumed.cookies.update(browser.cookies)
        persisted = settings["settings_fields"](resumed)
        for name in ("applicationName", settings["TOKEN"]):
            assert persisted[name] == saved[name]
        check_isolation(deployment)


def main():
    with tempfile.TemporaryDirectory(prefix="nergal-container-test-") as directory:
        root = Path(directory)
        credentials, tls = make_credentials(root)
        deployment = Deployment(root, credentials)
        subprocess.run(["sh", ROOT / "deploy/container/build.sh"], cwd=ROOT, env=deployment.env,
                       check=True, timeout=1200)
        try:
            deployment.own_credentials(credentials, OWNER)
            check_controller(deployment, tls)
        except Exception:
            deployment.compose("logs", "--no-color", "--tail", "80", check=False)
            raise
        finally:
            try:
                deployment.compose("down", "--volumes", "--remove-orphans")
            finally:
                try:
                    deployment.own_credentials(credentials, f"{os.getuid()}:{os.getgid()}")
                finally:
                    deployment.docker("image", "rm", deployment.image)
    print("PASS: verified loopback HTTPS, offline provisioning, private volumes, protected sessions and settings across restart and recreation, no controller capabilities")


if __name__ == "__main__":
    main()
