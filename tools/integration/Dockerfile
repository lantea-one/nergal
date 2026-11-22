# Disposable integration tooling only; no runtime image or host configuration.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 libgssapi-krb5-2 libicu76 libssl3t64 nftables \
    openssl python3 uidmap util-linux zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 fixture \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /tmp fixture \
    && printf 'fixture:100000:65536\n' > /etc/subuid \
    && printf 'fixture:100000:65536\n' > /etc/subgid
ENV PATH="/opt/dotnet:${PATH}" DOTNET_CLI_HOME=/tmp/dotnet-home DOTNET_NOLOGO=1
WORKDIR /workspace
