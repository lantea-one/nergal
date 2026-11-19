# Security

This project is in early development. It is not approved for production firewall
administration. The current web host is a read-only scaffold with no agent,
firewall-write endpoints or configured identity provider.

Do not include credentials, private keys, real policies or exported host state in
public issues or pull requests. Coordinate sensitive reports privately with the
maintainers through their published contact channels before disclosure.

Future releases require explicit authorization, per-user audit records, strict
agent/controller separation, scoped table ownership, validated transactions and
local timed rollback. These must have failure-path tests before deployment.
