FROM mcr.microsoft.com/dotnet/sdk:10.0.404@sha256:8c6edfb26c85153f236d26efebd9ad349aec403583f343f201ee67838b23658d AS build
WORKDIR /source
COPY global.json Directory.Build.props ./
COPY LICENSE scripts/collect-nuget-notices.py ./
COPY scripts/nuget-license-texts/ ./nuget-license-texts/
COPY deploy/LinuxRelease.targets ./LinuxRelease.targets
COPY src/ src/
RUN apt-get update --error-on=any \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
RUN dotnet restore src/Nergal.Web/Nergal.Web.csproj --locked-mode \
    && dotnet restore src/Nergal.Admin/Nergal.Admin.csproj --locked-mode \
    && dotnet publish src/Nergal.Web/Nergal.Web.csproj -c Release --no-restore -p:UseAppHost=false \
        -p:CustomAfterMicrosoftCommonTargets=/source/LinuxRelease.targets -o /publish/web \
    && dotnet publish src/Nergal.Admin/Nergal.Admin.csproj -c Release --no-restore -p:UseAppHost=false \
        -p:CustomAfterMicrosoftCommonTargets=/source/LinuxRelease.targets -o /publish/admin \
    && python3 -B collect-nuget-notices.py --output /publish/notices \
        --assets src/Nergal.Web/obj/project.assets.json --assets src/Nergal.Admin/obj/project.assets.json \
    && install -m 0644 LICENSE /publish/notices/LICENSE
# The SDK embeds compression time in its generated static asset HTTP metadata.
# Reproducible builds use the source revision timestamp for Last-Modified.
ARG SOURCE_DATE_EPOCH
RUN if [ -n "$SOURCE_DATE_EPOCH" ]; then \
      modified="$(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" '+%a, %d %b %Y %T GMT')" \
      && sed -i "s/\"Name\":\"Last-Modified\",\"Value\":\"[^\"]*\"/\"Name\":\"Last-Modified\",\"Value\":\"$modified\"/g" \
        /publish/web/Nergal.Web.staticwebassets.endpoints.json; \
    fi

FROM mcr.microsoft.com/dotnet/aspnet:10.0.15@sha256:aac50ceef10391e78a899e3d2ccd00bbafa2dcb56ccf4586cbccf00edb84fc21
# Docker populates fresh local named volumes with these directories and their
# ownership. The application validates modes/ownership on subsequent starts.
RUN install -d -o 1654 -g 1654 -m 0700 \
    /var/lib/nergal/state/accounts /var/lib/nergal/state/controller /var/lib/nergal/keyring/keys \
    && install -d -m 0755 /etc/nergal/credentials
COPY --from=build /publish/web /opt/nergal/web
COPY --from=build /publish/admin /opt/nergal/admin
COPY --from=build /publish/notices/ /usr/share/licenses/nergal/
COPY --chmod=0555 deploy/container/dotnet-private /usr/local/bin/dotnet-private
WORKDIR /opt/nergal/web
ENV ASPNETCORE_URLS=https://+:8443 \
    Kestrel__Certificates__Default__Path=/etc/nergal/credentials/https.crt \
    Kestrel__Certificates__Default__KeyPath=/etc/nergal/credentials/https.key \
    LocalSessions__Enabled=true \
    LocalSessions__AccountDirectory=/var/lib/nergal/state/accounts \
    LocalSessions__KeyDirectory=/var/lib/nergal/keyring/keys \
    LocalSessions__CertificateFile=/etc/nergal/credentials/wrapping.pfx \
    ControllerState__Enabled=true \
    ControllerState__Directory=/var/lib/nergal/state/controller \
    DOTNET_EnableDiagnostics=0
EXPOSE 8443/tcp
USER 1654:1654
ENTRYPOINT ["/usr/local/bin/dotnet-private", "/opt/nergal/web/Nergal.Web.dll"]
