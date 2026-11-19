"""End-to-end browser authorization against the live synthetic agent in the enclosing namespace fixture."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess


def verify_browser_status(root, dotnet, socket_path, count):
    # The caller has verified fresh user/network namespaces and subordinate IDs.
    source = Path(__file__).resolve().parents[3]
    session_spec = importlib.util.spec_from_file_location("session_fixture", source / "tests/integration/local-sessions/check.py")
    sessions = importlib.util.module_from_spec(session_spec)
    session_spec.loader.exec_module(sessions)
    framework = Path(shutil.which("dotnet")).resolve().parent / "shared/Microsoft.AspNetCore.App"
    runtime = Path(dotnet).parent
    shutil.copytree(framework, runtime / "shared/Microsoft.AspNetCore.App")
    web = root / "web"
    shutil.copytree(sessions.DLL.parent, web)
    for tree in (web, runtime / "shared/Microsoft.AspNetCore.App"):
        for directory, _, files in os.walk(tree):
            os.chmod(directory, 0o755)
            for filename in files:
                os.chmod(Path(directory) / filename, 0o644)

    profile = root / "controller"
    profile.mkdir(mode=0o700)
    tls = sessions.provision(profile)
    for directory, _, files in os.walk(profile):
        os.chown(directory, 1, 1)
        for filename in files:
            os.chown(Path(directory) / filename, 1, 1)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    settings = {"AgentStatus__Enabled": "true", "AgentStatus__ServerUserId": "0",
                "AgentStatus__SocketGroupId": "1", "AgentStatus__SocketPath": str(socket_path)}

    def drop():
        try:
            os.setgroups([])
        except PermissionError:
            pass
        os.setgid(1)
        os.setuid(1)

    before = count()
    with sessions.host(profile, tls, settings, executable=dotnet, dll=web / "Nergal.Web.dll", drop=drop) as browser:
        browser.request("/agent/status", 401)
        assert count() == before
        browser.login()
        assert 'href="/agent/status"' in browser.request("/session", 200)
        browser.request("/agent/status?command=other", 400)
        browser.request("/agent/status", 405, {})
        assert count() == before
        result = json.loads(browser.request("/agent/status", 200))
        assert result == {"schemaVersion": 1, "outcome": "matched", "revision": "1"}
        assert count() == before + 1
        # Only the enclosing disposable fixture owns this path. Keep the listener
        # alive while the configured path is missing, and restore it before teardown.
        parked = socket_path.with_name("parked.sock")
        socket_path.rename(parked)
        try:
            assert browser.request("/agent/status", 503) == ""
            assert count() == before + 1
        finally:
            parked.rename(socket_path)
        browser.request("/logout", 302, {"__RequestVerificationToken": browser.token("/session")})
        browser.request("/agent/status", 401)
        assert count() == before + 1
    print("PASS: authorized HTTPS session reads one verified peer snapshot; anonymous, invalid and logged-out requests never dispatch", flush=True)
