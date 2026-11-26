#!/usr/bin/env bash
# Install the two built packages in a disposable Arch root with dependencies installed.
set -euo pipefail
cd "${1:?Supply the staged AUR package directory}"

binary=(nergal-bin/*.pkg.tar.zst)
source=(nergal-git/*.pkg.tar.zst)
pacman -U --noconfirm "${binary[@]}"
test -x /usr/bin/nergal-admin
test -x /usr/bin/nergal-agent
test -f /usr/share/licenses/nergal-bin/LICENSE
test -f /usr/lib/systemd/system/nergal-web.service
test -z "$(find /etc/systemd/system -lname '*nergal*')"

if pacman -U --noconfirm "${source[@]}"; then
    echo 'Expected conflicting package installation to be refused' >&2
    exit 1
fi
pacman -Q nergal-bin
pacman -R --noconfirm nergal-bin
pacman -U --noconfirm "${source[@]}"
test -x /usr/bin/nergal-admin
test -x /usr/bin/nergal-agent
test -f /usr/share/licenses/nergal-git/LICENSE
test -f /usr/lib/systemd/system/nergal-agent-enroll.service
test -f /usr/lib/systemd/system/nergal-agent-reconcile.service
test -z "$(find /etc/systemd/system -lname '*nergal*')"
pacman -Q nergal-git
printf '%s\n' PASS-ARCH-AUR
