"""Verify a populated Overview chart using a real agent in a disposable network namespace."""

from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "local-sessions"))
from identity_https import Browser, sessions

AGENT = sessions.ROOT / "src/Nergal.Agent/bin/Release/net10.0/nergal-agent.dll"


def fixture_certificate(directory, name, purpose):
    certificate, key = (directory / f"{name}.{extension}" for extension in ("crt", "key"))
    subprocess.run(["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-x509", "-nodes", "-days", "1", "-subj", f"/CN={name}.example.test",
                    "-addext", "basicConstraints=critical,CA:FALSE",
                    "-addext", "keyUsage=critical,digitalSignature",
                    "-addext", f"extendedKeyUsage={purpose}", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", key, "-out", certificate], check=True, stderr=subprocess.DEVNULL)
    der = subprocess.check_output(["openssl", "x509", "-in", certificate, "-outform", "DER"])
    return certificate, key, hashlib.sha256(der).hexdigest()


@contextmanager
def agent_listener(state, certificate, key, client_pin):
    with subprocess.Popen(["dotnet", AGENT, "tls-serve", state, "127.0.0.1:0", certificate, key, client_pin],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            ready, _, _ = select.select([process.stdout], [], [], 10)
            line = process.stdout.readline().strip() if ready else ""
            assert line.startswith("LISTENING 127.0.0.1:"), "Synthetic pinned agent failed to listen"
            yield line.removeprefix("LISTENING ")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)


def register_host(browser, host, endpoint, pin):
    token = browser.token("/session")
    connection = http.client.HTTPSConnection("127.0.0.1", host.ports["https"], context=host.tls, timeout=10)
    headers = {"Content-Type": "application/json", "RequestVerificationToken": token,
               "Cookie": "; ".join(f"{name}={value}" for name, value in browser.cookies.items())}
    try:
        connection.request("POST", "/controller/hosts", json.dumps({
            "name": "synthetic-observed-host", "transportKind": "tls",
            "endpoint": endpoint, "pinnedServerThumbprint": pin,
        }), headers)
        response = connection.getresponse()
        response.read()
        assert response.status == 201, f"Fixture registration failed with {response.status}"
    finally:
        connection.close()


def exercise(directory):
    tls = sessions.provision(directory)
    agent_state = directory / "agent"
    controller_state = directory / "controller"
    for state in (agent_state, controller_state):
        state.mkdir(mode=0o700)
    subprocess.run(["dotnet", AGENT, "enroll", agent_state], check=True)
    subprocess.run(["dotnet", sessions.ADMIN_TOOL, "controller", "init", controller_state], check=True)
    server_cert, server_key, server_pin = fixture_certificate(directory, "agent", "serverAuth")
    client_cert, client_key, client_pin = fixture_certificate(directory, "controller", "clientAuth")

    settings = {"ControllerState__Enabled": "true", "ControllerState__Directory": str(controller_state),
                "ControllerState__TlsClientCertificatePath": str(client_cert),
                "ControllerState__TlsClientKeyPath": str(client_key)}
    with sessions.host(directory, tls, settings) as host:
        browser = Browser(host)
        browser.login(destination="/manage")
        assert "No hosts connected." in browser.request("/manage", 200)
        with agent_listener(agent_state, server_cert, server_key, client_pin) as endpoint:
            register_host(browser, host, endpoint, server_pin)
            overview = browser.request("/manage", 200)
            assert "1 of 1 registered hosts classified by agent status" in overview
            assert "Baseline matches" in overview and '<meter min="0" max="1" value="1"' in overview

        # A lost connection must not be charted using the prior authenticated result.
        overview = browser.request("/manage", 200)
        assert "Status unavailable" in overview and "No usable agent status" in overview
        assert "<meter " not in overview
    print("PASS: populated Overview from real pinned agent status, then explicit coverage gap")


if __name__ == "__main__":
    parent = sys.argv[1:]
    actual = [os.readlink(f"/proc/self/ns/{name}") for name in ("user", "net")]
    if len(parent) != 2 or any(inside == outside for inside, outside in zip(actual, parent)):
        raise SystemExit("Run in fresh user and network namespaces with both original namespace identities.")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-overview-") as directory:
        exercise(Path(directory))
