#!/bin/sh
set -eu
port=$1
sed "s/@PORT@/$port/g" /opt/fixture/directory.ldif > /directory/seed.ldif
slapadd -f /opt/fixture/slapd.conf -l /directory/seed.ldif
exec slapd -d 0 -f /opt/fixture/slapd.conf -h "ldaps://127.0.0.1:$port/"
