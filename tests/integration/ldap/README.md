# Disposable OpenLDAP over LDAPS

On Linux, use Bash, OpenSSL, Python 3, GNU `timeout`, and a local Docker Engine
with Buildx, host networking and access to temporary bind mounts. Building the
fixture image needs access to Docker Hub and the Debian package mirrors. Use the
repository's pinned .NET 10 SDK and a completed Release build for the xUnit run.

```sh
bash tests/integration/ldap/check-openldap.sh --check-directory
bash tests/integration/ldap/check-openldap.sh
```

The first command starts OpenLDAP and checks its TLS name and CA, real binds,
the administrator's access to its own `entryUUID`, and both kinds of LDAP referral
response. The second command also runs the opt-in xUnit tests from the Release
build. The trusted pass includes `LdapDirectoryIntegrationTests` and
`LdapWireLoopbackTests`. It exposes the synthetic leaf certificate and key as
`NERGAL_LDAP_FIXTURE_TLS_CERTIFICATE` and `NERGAL_LDAP_FIXTURE_TLS_KEY` for local
loopback servers. A fresh test process uses a separate, unrelated CA for
`DeniesUntrustedPeer`. Trust is supplied through `SSL_CERT_FILE` and an empty
`SSL_CERT_DIR`. Ordinary unit runs skip the OpenLDAP tests.

The fixture uses a random high loopback port and a disposable MDB database in
container tmpfs. Docker uses host networking to make that listener available to
the test process without published ports. The only bind mount is a read-only
temporary directory with synthetic certificate material. The script bounds its
build, readiness, tests and cleanup, then removes the container and temporary
files. Docker may retain the built image and package layers in its cache.

`directory.ldif` contains only public synthetic entries and passwords. Both
groups use `groupOfNames` with direct `member` links. One user occurs only in the
administrator group's `owner` attribute, two entries share a login, and one user
belongs to both groups. The reader account can search entries and compare group
membership. A bound user can read its own entry UUID, and fixture binds grant no
directory writes. The broad-base referral case returns the valid administrator
entry alongside an LDAP search reference.

The default runner also starts a disposable loopback HTTPS controller and
exercises LDAP sign-in, TOTP and persistence after restart. Use `--check-web`
to run only the controller scenario after checking directory readiness. The
separate local TOTP scenario runs with
`python3 -B tests/integration/local-sessions/check-totp.py`.
