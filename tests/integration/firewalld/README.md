# Isolated firewalld assessment

Tested: firewalld 2.4.1 from Alpine 3.24. The Dockerfile distribution tag is not
an immutable package snapshot; reruns must record their actual version and
reassess changed behavior. result.log is the recorded research result, not a
claim about another version. check.sh is original test code.

```sh
docker build -t nergal-firewalld-assessment tests/integration/firewalld
docker run --rm --network none --cap-add NET_ADMIN \
  -v "$PWD/tests/integration/firewalld/check.sh:/check.sh:ro" \
  nergal-firewalld-assessment sh /check.sh
```

The container starts its own D-Bus and firewalld. NET_ADMIN applies only inside
its disposable network namespace. Never add host networking, host PID namespace,
Docker socket or host system-bus mounts. The first attempt using a fully dropped
capability set did not start correctly; the fixture therefore uses ordinary
Docker capabilities plus NET_ADMIN within the isolated container.

The check confirms supported basic configuration and preservation of foreign
tables on ordinary reload, then examines rate-limit semantics and rejection of
unsupported rich-rule elements. It does not modify host firewall configuration
or prove full packet-level behavioral equivalence.
