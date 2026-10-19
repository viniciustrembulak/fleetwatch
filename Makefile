LAB := docker compose -f lab/docker-compose.yml
FW  := FW_UID=$$(id -u) FW_GID=$$(id -g) $(LAB) run --rm fleetwatch

.PHONY: help lab-up lab-down baseline attack scan demo test lint

help:  ## mostra os comandos disponíveis
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

lab/keys/fleetwatch:
	mkdir -p lab/keys
	ssh-keygen -q -t ed25519 -N '' -C fleetwatch-lab -f lab/keys/fleetwatch

lab-up: lab/keys/fleetwatch  ## sobe os 3 hosts do laboratório
	$(LAB) up -d --build pdv-01 pdv-02 pdv-03
	$(LAB) build fleetwatch

lab-down:  ## derruba o laboratório e apaga baselines/relatórios
	$(LAB) --profile cli down -v
	rm -rf lab/baselines lab/reports

baseline:  ## registra a baseline dos hosts
	$(FW) baseline

attack:  ## simula um comprometimento em pdv-02 e pdv-03
	sh lab/simulate-attack.sh

scan:  ## compara os hosts com a baseline e gera relatórios
	$(FW) scan --json reports/scan-{ts}.json --html reports/scan-{ts}.html

demo: lab-up baseline attack  ## ciclo completo: sobe, baseline, ataque e scan
	-$(MAKE) scan

test:  ## roda os testes
	pytest -q

lint:  ## roda o ruff
	ruff check src tests
