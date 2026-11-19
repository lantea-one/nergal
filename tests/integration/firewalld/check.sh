#!/bin/sh
set -eu
mkdir -p /run/dbus
dbus-daemon --system --fork
firewalld --nofork --nopid --debug=1 --log-target=console > /tmp/firewalld.log 2>&1 &
ready=0
for attempt in $(seq 1 50); do
 if firewall-cmd --state >/dev/null 2>&1; then ready=1; break; fi
 sleep 0.2
done
if [ "$ready" != 1 ]; then tail -25 /tmp/firewalld.log; exit 1; fi
firewall-cmd --version
nft add table inet external_filter
nft add chain inet external_filter sentinel
nft add rule inet external_filter sentinel counter comment keep-me
nft add table bridge external_bridge
nft add table ip external_nat
firewall-cmd --permanent --new-zone=nergal-test
firewall-cmd --permanent --zone=nergal-test --add-source=192.0.2.0/24
firewall-cmd --permanent --zone=nergal-test --add-port=443/tcp
firewall-cmd --permanent --zone=nergal-test --add-rich-rule='rule family="ipv4" port port="22" protocol="tcp" accept limit value="3/m"'
firewall-cmd --permanent --zone=nergal-test --add-rich-rule='rule family="ipv6" source address="2001:db8::/64" forward-port port="443" protocol="tcp" to-port="8443" to-addr="2001:db8:1::2"'
firewall-cmd --reload
nft list table inet external_filter | grep -q keep-me
nft list table bridge external_bridge >/dev/null
nft list table ip external_nat >/dev/null
firewall-cmd --zone=nergal-test --query-port=443/tcp
nft -j list table inet firewalld > /tmp/firewalld.json
python3 - <<'PY'
import json
from firewall.core.rich import Rich_Rule
with open('/tmp/firewalld.json') as f:data=json.load(f)
limited=[x['rule'] for x in data['nftables'] if 'rule' in x and any('limit' in e for e in x['rule'].get('expr',[]))]
assert limited, 'Expected rate-limited generated rule'
print('Generated rich-rule limit expressions:', [e for r in limited for e in r['expr'] if 'limit' in e])
assert not any('meter' in e for r in limited for e in r['expr'])
for label,rule in [
 ('original connection tuple','rule family="ipv4" conntrack original-destination="198.51.100.10" accept'),
 ('explicit source NAT','rule family="ipv4" source address="192.0.2.0/24" snat to-addr="198.51.100.20"'),
 ('per-source meter','rule family="ipv4" port port="22" protocol="tcp" accept limit value="3/m" per-source="true"'),
]:
 try: Rich_Rule(rule_str=rule)
 except Exception as e: print(label+': not expressible with the requested rich-rule element:', str(e))
 else: raise AssertionError(label+' unexpectedly accepted; inspect support before deciding')
print('PASS: ordinary reload preserved all three unrelated tables and applied the basic policy.')
print('LIMITATION: supported rich-rule limit is a shared rule bucket, not an nftables per-source meter.')
PY
