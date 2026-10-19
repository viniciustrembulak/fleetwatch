#!/bin/sh
set -e

# Cada container gera as próprias chaves de host na primeira subida.
ssh-keygen -A >/dev/null

if [ -f /keys/fleetwatch.pub ]; then
    install -d -m 700 -o auditor -g auditor /home/auditor/.ssh
    install -m 600 -o auditor -g auditor /keys/fleetwatch.pub /home/auditor/.ssh/authorized_keys
fi

cron
exec /usr/sbin/sshd -D -e
