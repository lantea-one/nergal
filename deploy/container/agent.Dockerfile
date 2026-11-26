FROM mcr.microsoft.com/dotnet/sdk:10.0.404@sha256:8c6edfb26c85153f236d26efebd9ad349aec403583f343f201ee67838b23658d AS publish
WORKDIR /source
COPY global.json Directory.Build.props ./
COPY LICENSE scripts/collect-nuget-notices.py ./
COPY scripts/nuget-license-texts/ ./nuget-license-texts/
COPY deploy/LinuxRelease.targets ./LinuxRelease.targets
COPY src/ src/
RUN apt-get update --error-on=any \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
RUN dotnet restore src/Nergal.Agent/Nergal.Agent.csproj --locked-mode \
    && dotnet publish src/Nergal.Agent/Nergal.Agent.csproj -c Release --no-restore \
        -p:UseAppHost=false -p:CustomAfterMicrosoftCommonTargets=/source/LinuxRelease.targets -o /publish/agent \
    && python3 -B collect-nuget-notices.py --output /publish/notices \
        --assets src/Nergal.Agent/obj/project.assets.json \
    && install -m 0644 LICENSE /publish/notices/LICENSE

# Resolute supplies nftables 1.1.6 and setpriv. Pin both the AMD64 runtime
# manifest and the signed Ubuntu archive used to resolve native dependencies.
FROM mcr.microsoft.com/dotnet/runtime:10.0.15-resolute-amd64@sha256:93bc80d0108e8efb514bec6212e3ea83ca45abd611a88450f95d3ea3d1307115 AS runtime-base
RUN test "$(dpkg --print-architecture)" = amd64 \
    && printf '%s\n' \
        'Types: deb' \
        'URIs: https://snapshot.ubuntu.com/ubuntu/20261124T000000Z/' \
        'Suites: resolute resolute-updates resolute-security' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' > /etc/apt/sources.list.d/ubuntu.sources

FROM runtime-base AS supervisor
RUN apt-get update --error-on=any \
    && apt-get install -y --no-install-recommends gcc libc6-dev
COPY deploy/container/agent-supervisor.c /src/agent-supervisor.c
RUN cc -std=c17 -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
    -fPIE -pie -Wl,-z,relro,-z,now -o /agent-supervisor /src/agent-supervisor.c

FROM runtime-base
RUN apt-get update --error-on=any \
    && apt-get install -y --no-install-recommends nftables=1.1.6-1 \
    && test -x /usr/bin/setpriv && /usr/sbin/nft --version \
    && rm -rf /var/lib/apt/lists/* /var/log/apt/* /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache \
    && install -d -o 1654 -g 1654 -m 0700 /var/lib/nergal/agent /etc/nergal/agent/private
COPY --from=publish /publish/agent/ /opt/nergal/agent/
COPY --from=publish /publish/notices/ /usr/share/licenses/nergal/
COPY --from=supervisor --chmod=0555 /agent-supervisor /usr/local/libexec/nergal-agent-supervisor
COPY --chmod=0555 deploy/container/agent-entrypoint /usr/local/bin/nergal-agent-entrypoint
ENV DOTNET_EnableDiagnostics=0
WORKDIR /opt/nergal/agent
# Only the fixed setpriv launcher starts as root. All agent commands, their
# native nft subprocesses and independent watchdogs execute as UID/GID 1654.
USER 0:0
ENTRYPOINT ["/usr/local/bin/nergal-agent-entrypoint"]
CMD ["--help"]
