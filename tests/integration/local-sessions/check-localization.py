"""Exercise the translated MVC host and audit workflow through loopback HTTPS."""

import http.client
from html import unescape
from http.cookies import SimpleCookie
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlencode

from check import ADMIN_TOOL, host, provision

LANGUAGE = "nergal-language"
HOSTS = "/manage/hosts"


def select_language(browser, fields, expected):
    # The shared session fixture deliberately accepts only authentication/antiforgery cookies.
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Cookie": "; ".join(f"{key}={value}" for key, value in browser.cookies.items())}
    connection = http.client.HTTPSConnection("127.0.0.1", browser.ports["https"], context=browser.tls, timeout=10)
    try:
        connection.request("POST", "/language", urlencode(fields), headers)
        response = connection.getresponse()
        response.read()
        assert response.status == expected, response.status
        cookies = SimpleCookie()
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                cookies.load(value)
        if expected == 302:
            assert set(cookies) == {LANGUAGE}
            cookie = cookies[LANGUAGE]
            assert cookie["httponly"] and cookie["secure"] and cookie["samesite"].lower() == "lax"
            assert cookie["path"] == "/" and cookie["max-age"] == str(180 * 86400) and not cookie["domain"]
            browser.cookies[LANGUAGE] = cookie.value
        else:
            assert LANGUAGE not in cookies
        return response.getheader("Location")
    finally:
        connection.close()


def exercise(temp):
    tls = provision(temp)
    state = temp / "controller"
    state.mkdir(mode=0o700)
    subprocess.run(["dotnet", ADMIN_TOOL, "controller", "init", state], check=True)
    with host(temp, tls, {"ControllerState__Enabled": "true", "ControllerState__Directory": str(state)}) as browser:
        login = browser.request("/login?culture=es-ES", 200, headers={"Accept-Language": "es-ES"})
        assert '<html lang="en-US"' in login
        token = browser.token("/login")
        fields = {"culture": "es-ES", "returnPath": "/login", "__RequestVerificationToken": token}
        select_language(browser, {"culture": "es-ES"}, 400)
        select_language(browser, {**fields, "culture": "es"}, 400)
        select_language(browser, [*fields.items(), ("culture", "en-US")], 400)
        assert select_language(browser, {**fields, "returnPath": "//example.invalid/"}, 302) == "/"
        assert select_language(browser, fields, 302) == "/login"
        browser.login()
        denied = unescape(browser.request("/missing-localization-fixture", 404, headers={"Accept": "text/html"}))
        assert "Página no encontrada" in denied and browser.last_headers["content-language"] == "es-ES"

        hosts = unescape(browser.request(HOSTS, 200))
        assert '<html lang="es-ES"' in hosts and 'name="returnPath" value="/manage/hosts"' in hosts
        assert "Saltar al contenido" in hosts and "Navegación principal" in hosts and "<span>NAT</span>" in hosts
        assert '<label for="host-name">Nombre del equipo</label>' in hosts
        assert 'aria-describedby="host-name-help"' in hosts and "Usa letras, dígitos" in hosts

        fields = {"name": "locale-fixture", "transportKind": "unix", "endpoint": "/run/nergal-fixture/control.sock",
                  "expectedServerUserId": "invalid", "__RequestVerificationToken": browser.token(HOSTS)}
        invalid = unescape(browser.request(HOSTS + "/add", 400, fields))
        assert 'role="alert">El UID esperado del servidor no es válido.' in invalid
        assert "Equipos administrados (0)" in invalid
        browser.request(HOSTS + "/add", 302, {**fields, "expectedServerUserId": "0"})
        registered = unescape(browser.request(HOSTS, 200))
        assert 'data-host-state="unavailable">No disponible' in registered
        assert 'locale-fixture' in registered and '/run/nergal-fixture/control.sock' in registered

        audit = unescape(browser.request("/manage/audit", 200))
        assert "Auditoría del controlador e historial de revisiones" in audit
        utc = re.search(r'data-local-time datetime="(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)" title="Hora almacenada en UTC: ([^"]+)"', audit)
        assert utc and utc[1] == utc[2]

        assert select_language(browser, {"culture": "en-US", "returnPath": HOSTS,
                                         "__RequestVerificationToken": browser.token(HOSTS)}, 302) == HOSTS
        english = browser.request(HOSTS, 200)
        assert '<html lang="en-US"' in english and "Register agent host" in english
        assert 'data-host-state="unavailable">unavailable' in english


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="nergal-localization-") as directory:
        exercise(Path(directory))
    print("PASS: MVC language selection, validation, host status, and audit UTC across English and Spanish")
