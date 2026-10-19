# Simula um host da frota (ex.: um PDV) com SSH e algumas ferramentas comuns.
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server sudo iproute2 netcat-openbsd procps cron \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_*

# Usuário de auditoria usado pelo fleetwatch (somente chave, sem senha).
# Em produção, restrinja o sudoers ao mínimo necessário.
RUN useradd -m -s /bin/bash auditor \
 && passwd -l auditor \
 && echo 'auditor ALL=(root) NOPASSWD: /bin/sh -s' > /etc/sudoers.d/auditor \
 && chmod 0440 /etc/sudoers.d/auditor \
 && useradd -m -s /bin/bash operador \
 && mkdir -p /run/sshd \
 && sed -i -E \
      -e 's/^#?PasswordAuthentication .*/PasswordAuthentication no/' \
      -e 's/^#?PermitRootLogin .*/PermitRootLogin no/' \
      /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
