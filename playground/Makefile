# Shortcuts for the playground. Each target just runs the docker compose command shown in README.md.
DC = docker compose

.PHONY: help site up traffic match banner logs down reset

help:
	@echo "make site     build the website + plant tokens (registry in state/)"
	@echo "make up       start the web server (http://localhost:8080)"
	@echo "make traffic  run all simulated visitors once, in order"
	@echo "make match    match logs against the token registry, write logs/analysis/"
	@echo "make banner   also start Apache (http://localhost:8081) for the banner exercise"
	@echo "make logs     follow the JSON access log"
	@echo "make down     stop everything"
	@echo "make reset    stop and delete logs, site, registry and token secret"

site:
	$(DC) run --rm builder

up: site
	$(DC) up -d web

traffic:
	$(DC) run --rm polite
	$(DC) run --rm rude
	$(DC) run --rm scanner
	$(DC) run --rm fakebot
	$(DC) run --rm resolver

match:
	$(DC) run --rm matcher

banner:
	$(DC) --profile banner up -d apache

logs:
	tail -f logs/nginx/access.json

down:
	$(DC) --profile banner --profile tools down

reset: down
	rm -rf logs/nginx logs/apache logs/analysis logs/*.jsonl
	find site state -mindepth 1 ! -name .gitkeep -delete
