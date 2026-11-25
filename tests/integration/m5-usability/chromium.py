"""Minimal W3C WebDriver client for a fresh, local Chromium session."""

import base64
from contextlib import contextmanager
import http.client
import json
import os
import re
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


class Browser:
    def __init__(self, port):
        self.port = port
        self.session = ""

    def request(self, method, path, payload=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            connection.request(
                method, self.session + path,
                None if payload is None else json.dumps(payload),
                {"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            value = json.loads(response.read())["value"]
            if response.status != 200:
                raise RuntimeError(f"WebDriver {method} {path}: {value['message'].splitlines()[0]}")
            return value
        finally:
            connection.close()

    def post(self, path, **payload):
        return self.request("POST", path, payload)

    def evaluate(self, script, *args):
        return self.post("/execute/sync", script=script, args=args)

    def cdp(self, command, **params):
        return self.post("/goog/cdp/execute", cmd=command, params=params)

    def element(self, selector):
        element = self.post("/element", using="css selector", value=selector)
        return "/element/" + element["element-6066-11e4-a52e-4f735466cecf"]

    def click(self, selector):
        try:
            self.post(self.element(selector) + "/click")
        except RuntimeError as error:
            raise RuntimeError(f"Cannot click {selector} at {self.path()}: {error}") from error

    def fill(self, selector, value):
        element = self.element(selector)
        self.post(element + "/clear")
        self.post(element + "/value", text=value)

    def select(self, selector, value):
        self.click(f'{selector} option[value="{value}"]')
        assert self.value(selector) == value, f"{selector} did not select {value}"

    def upload(self, selector, path):
        self.post(self.element(selector) + "/value", text=str(path))

    def key(self, key):
        self.post("/actions", actions=[{
            "type": "key", "id": "keyboard",
            "actions": [{"type": "keyDown", "value": key}, {"type": "keyUp", "value": key}],
        }])

    def visible(self, selector):
        return self.evaluate(
            "return [...document.querySelectorAll(arguments[0])].some(e => "
            "e.checkVisibility({checkVisibilityCSS: true}));", selector
        )

    def value(self, selector):
        return self.evaluate("return document.querySelector(arguments[0]).value;", selector)

    def text(self, selector="main"):
        return self.evaluate(
            "const node = document.querySelector(arguments[0]); "
            "return node?.checkVisibility({checkVisibilityCSS: true}) ? node.innerText : '';",
            selector,
        )

    def location(self):
        return urlsplit(self.request("GET", "/url"))

    def path(self):
        return self.location().path

    def wait_for(self, condition, message):
        deadline = time.monotonic() + 5
        while not condition():
            if time.monotonic() >= deadline:
                raise AssertionError(f"{message} at {self.path()}")
            time.sleep(0.05)

    def wait_for_path(self, expected):
        self.wait_for(lambda: self.path() == expected, f"Expected navigation to {expected}")

    def screenshot(self, path):
        path.write_bytes(base64.b64decode(self.request("GET", "/screenshot")))


@contextmanager
def launch(driver, binary, temp, tls_pin):
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            [driver, "--port=0", "--allowed-ips=127.0.0.1"], stdout=log, stderr=subprocess.STDOUT
        )
        browser = None
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                output = os.pread(log.fileno(), 16384, 0).decode(errors="replace")
                match = re.search(r"ChromeDriver was started successfully on port (\d+)", output)
                if match:
                    browser = Browser(int(match[1]))
                    break
                if process.poll() is not None:
                    raise RuntimeError("ChromeDriver exited before starting")
                time.sleep(0.05)
            if browser is None:
                raise RuntimeError("ChromeDriver did not announce a loopback port")
            session = browser.post("/session", capabilities={"alwaysMatch": {
                "browserName": "chrome",
                "goog:chromeOptions": {"binary": binary, "args": [
                    "--headless", "--no-first-run", "--disable-background-networking",
                    "--disable-component-update", "--disable-sync", "--no-proxy-server",
                    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                    f"--user-data-dir={temp / 'browser'}",
                    f"--ignore-certificate-errors-spki-list={tls_pin}",
                ]},
            }})
            browser.session = "/session/" + session["sessionId"]
            browser.version = session["capabilities"]["browserVersion"]
            browser.post("/timeouts", pageLoad=12000, script=10000, implicit=1000)
            browser.cdp("Emulation.setTimezoneOverride", timezoneId="Pacific/Honolulu")
            browser.cdp("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "light"}])
            yield browser
        finally:
            try:
                if browser is not None and browser.session:
                    browser.request("DELETE", "")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
