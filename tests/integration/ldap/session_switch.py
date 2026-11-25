"""Switch from a local Administrator to a directory Auditor on the disposable HTTPS host."""
from identity_https import Browser, CSRF, sessions


def exercise_local_switch(host, admin, password):
    path = "/manage/identity/ldap"
    version = admin.form(path, path + "/save")["version"]
    copied = Browser(host)
    copied.cookies[sessions.ADMIN] = admin.cookies[sessions.ADMIN]
    fields = {"version": version, "username": "auditor", CSRF: admin.token("/session")}
    admin.post("/login/ldap", {**fields, "password": "synthetic-wrong-password"}, 401)
    copied.request("/manage/users", 200)
    admin.post("/login/ldap", {**fields, "password": password}, 302, destination="/session")
    assert sessions.ADMIN not in admin.cookies and "__Host-nergal-ldap" in admin.cookies
    admin.request("/session", 200)
    admin.request("/manage/users", 403)
    copied.assert_anonymous()
