#!/bin/bash
set -euo pipefail
umask 077

media=$1
phase=$2
shift 2
config=/etc/nergal/web
state=/var/lib/nergal/web
private=$config/private

client_paths() {
    printf 'ControllerState__TlsClientCertificatePath=%s/client-%s.crt\n' "$private" "$1"
    printf 'ControllerState__TlsClientKeyPath=%s/client-%s.key\n' "$private" "$1"
}

case "$phase" in
    init)
        install -d -o nergal-web -g nergal-web -m 0700 "$state"/{accounts,controller,keys} "$private"
        runuser -u nergal-web -- nergal-admin account init "$state/accounts"
        runuser -u nergal-web -- nergal-admin account provision "$state/accounts" fixture-admin --password-stdin \
            < /run/nergal-ops/password
        runuser -u nergal-web -- nergal-admin controller init "$state/controller"
        openssl req -x509 -newkey rsa:3072 -nodes -days 2 -subj '/CN=nergal-controller.invalid' \
            -addext 'subjectAltName=IP:127.0.0.1' -keyout "$config/tls.key" \
            -out "$config/tls.crt" 2>/dev/null
        openssl req -x509 -newkey rsa:3072 -nodes -days 2 -subj '/CN=nergal-wrap.invalid' \
            -keyout "$private/wrapping.key" -out "$private/wrapping.crt" 2>/dev/null
        openssl pkcs12 -export -inkey "$private/wrapping.key" -in "$private/wrapping.crt" \
            -out "$private/wrapping.pfx" -passout pass:
        rm "$private/wrapping.key" "$private/wrapping.crt"
        chown nergal-web:nergal-web "$config"/tls.{crt,key} "$private/wrapping.pfx"
        for name in first second; do
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
                -subj "/CN=nergal-client-$name.invalid" -addext 'basicConstraints=critical,CA:FALSE' \
                -addext 'keyUsage=critical,digitalSignature' -addext 'extendedKeyUsage=clientAuth' \
                -keyout "$private/client-$name.key" -out "$private/client-$name.crt" 2>/dev/null
            chown nergal-web:nergal-web "$private/client-$name".{crt,key}
            pin=$(openssl x509 -in "$private/client-$name.crt" -outform DER | sha256sum | cut -d ' ' -f 1)
            printf 'CLIENT_%s_PIN=%s\n' "${name^^}" "$pin"
        done
        cat > "$config/env" <<EOF_ENV
ASPNETCORE_URLS=https://127.0.0.1:8443
Kestrel__Certificates__Default__Path=$config/tls.crt
Kestrel__Certificates__Default__KeyPath=$config/tls.key
LocalSessions__Enabled=true
LocalSessions__AccountDirectory=$state/accounts
LocalSessions__KeyDirectory=$state/keys
LocalSessions__CertificateFile=$private/wrapping.pfx
ControllerState__Enabled=true
ControllerState__Directory=$state/controller
EOF_ENV
        client_paths first >> "$config/env"
        systemctl start nergal-web.service
        ;;
    start) systemctl start nergal-web.service ;;
    client)
        case "$1" in first|second) ;; *) exit 2 ;; esac
        sed -i '/^ControllerState__TlsClient\(Certificate\|Key\)Path=/d' "$config/env"
        client_paths "$1" >> "$config/env"
        systemctl restart nergal-web.service
        ;;
    register|probe|retire|save|verify)
        python3 -B "$media/multihost-controller.py" "$phase" "$@"
        ;;
    *) exit 2 ;;
esac
