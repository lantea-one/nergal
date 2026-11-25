FROM debian:bookworm-slim

RUN export DEBIAN_FRONTEND=noninteractive \
    && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && printf 'slapd slapd/no_configuration boolean true\n' | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends slapd ldap-utils \
    && rm -rf /var/lib/apt/lists/*

COPY slapd.conf directory.ldif serve.sh /opt/fixture/

ENTRYPOINT ["/bin/sh", "/opt/fixture/serve.sh"]
