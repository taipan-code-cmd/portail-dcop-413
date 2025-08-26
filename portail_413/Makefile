# DCOP (413) - Portail des Visites
# Makefile pour automatiser les tâches de développement et déploiement

.PHONY: help build test clean dev deploy backup restore logs status

# Variables
PROJECT_NAME = dcop_413
DOCKER_COMPOSE = docker-compose
CARGO = cargo

# Couleurs pour les messages
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

# Aide par défaut
help: ## Afficher cette aide
	@echo "$(GREEN)DCOP (413) - Portail des Visites$(NC)"
	@echo "$(YELLOW)Commandes disponibles :$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Développement
dev: ## Démarrer en mode développement
	@echo "$(YELLOW)Démarrage en mode développement...$(NC)"
	$(CARGO) run

build: ## Compiler l'application
	@echo "$(YELLOW)Compilation de l'application...$(NC)"
	$(CARGO) build --release

test: ## Exécuter les tests
	@echo "$(YELLOW)Exécution des tests...$(NC)"
	$(CARGO) test

test-coverage: ## Exécuter les tests avec couverture
	@echo "$(YELLOW)Tests avec couverture de code...$(NC)"
	$(CARGO) test --all-features --no-fail-fast
	$(CARGO) tarpaulin --out Html

lint: ## Vérifier le code avec clippy
	@echo "$(YELLOW)Vérification du code...$(NC)"
	$(CARGO) clippy -- -D warnings

format: ## Formater le code
	@echo "$(YELLOW)Formatage du code...$(NC)"
	$(CARGO) fmt

clean: ## Nettoyer les fichiers de build
	@echo "$(YELLOW)Nettoyage...$(NC)"
	$(CARGO) clean
	$(DOCKER_COMPOSE) down --volumes --remove-orphans
	docker system prune -f

# Docker et déploiement
docker-build: ## Construire les images Docker
	@echo "$(YELLOW)Construction des images Docker...$(NC)"
	$(DOCKER_COMPOSE) build --no-cache

deploy: ## Déployer l'application
	@echo "$(YELLOW)Déploiement de l'application...$(NC)"
	chmod +x scripts/deploy.sh
	./scripts/deploy.sh

start: ## Démarrer les services Docker
	@echo "$(YELLOW)Démarrage des services...$(NC)"
	$(DOCKER_COMPOSE) up -d

stop: ## Arrêter les services Docker
	@echo "$(YELLOW)Arrêt des services...$(NC)"
	$(DOCKER_COMPOSE) down

restart: ## Redémarrer les services Docker
	@echo "$(YELLOW)Redémarrage des services...$(NC)"
	$(DOCKER_COMPOSE) restart

# Monitoring et logs
logs: ## Afficher les logs de l'application
	$(DOCKER_COMPOSE) logs -f dcop_app

logs-db: ## Afficher les logs de la base de données
	$(DOCKER_COMPOSE) logs -f postgres

logs-nginx: ## Afficher les logs Nginx
	$(DOCKER_COMPOSE) logs -f nginx

logs-all: ## Afficher tous les logs
	$(DOCKER_COMPOSE) logs -f

status: ## Afficher le statut des services
	@echo "$(YELLOW)Statut des services :$(NC)"
	$(DOCKER_COMPOSE) ps

health: ## Vérifier la santé des services
	@echo "$(YELLOW)Vérification de la santé des services...$(NC)"
	@curl -f -k https://localhost/health && echo "$(GREEN)✓ Application OK$(NC)" || echo "$(RED)✗ Application KO$(NC)"
	@$(DOCKER_COMPOSE) exec postgres pg_isready -U dcop_user -d dcop_413 && echo "$(GREEN)✓ PostgreSQL OK$(NC)" || echo "$(RED)✗ PostgreSQL KO$(NC)"

# Base de données
db-migrate: ## Exécuter les migrations
	@echo "$(YELLOW)Exécution des migrations...$(NC)"
	$(DOCKER_COMPOSE) exec dcop_app ./portail_413 migrate

db-reset: ## Réinitialiser la base de données
	@echo "$(RED)ATTENTION: Cette action va supprimer toutes les données !$(NC)"
	@read -p "Êtes-vous sûr ? (y/N) " -n 1 -r; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		$(DOCKER_COMPOSE) down postgres; \
		docker volume rm portail_413_postgres_data; \
		$(DOCKER_COMPOSE) up -d postgres; \
		sleep 10; \
		$(MAKE) db-migrate; \
	fi

db-backup: ## Sauvegarder la base de données
	@echo "$(YELLOW)Sauvegarde de la base de données...$(NC)"
	chmod +x scripts/backup.sh
	./scripts/backup.sh

db-shell: ## Accéder au shell PostgreSQL
	$(DOCKER_COMPOSE) exec postgres psql -U dcop_user -d dcop_413

# Sécurité
security-scan: ## Scanner les vulnérabilités
	@echo "$(YELLOW)Scan de sécurité...$(NC)"
	$(CARGO) audit
	docker run --rm -v $(PWD):/app clair-scanner:latest --ip $(shell hostname -I | awk '{print $$1}') $(PROJECT_NAME):latest

generate-ssl: ## Générer des certificats SSL auto-signés
	@echo "$(YELLOW)Génération des certificats SSL...$(NC)"
	mkdir -p nginx/ssl
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout nginx/ssl/key.pem \
		-out nginx/ssl/cert.pem \
		-subj "/C=CD/ST=Kinshasa/L=Kinshasa/O=DCOP/OU=IT/CN=localhost"
	chmod 600 nginx/ssl/key.pem
	chmod 644 nginx/ssl/cert.pem
	@echo "$(GREEN)Certificats générés dans nginx/ssl/$(NC)"

# Maintenance
update: ## Mettre à jour les dépendances
	@echo "$(YELLOW)Mise à jour des dépendances...$(NC)"
	$(CARGO) update
	$(DOCKER_COMPOSE) pull

backup: ## Sauvegarde complète
	@echo "$(YELLOW)Sauvegarde complète...$(NC)"
	chmod +x scripts/backup.sh
	./scripts/backup.sh

# Installation sécurisée
install: ## Installation complète sécurisée
	@echo "$(YELLOW)Installation sécurisée de DCOP (413)...$(NC)"
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(YELLOW)Fichier .env créé. Modifiez-le avant le déploiement !$(NC)"; \
	fi
	$(MAKE) generate-secrets
	$(MAKE) generate-ssl
	$(MAKE) init-db
	$(MAKE) deploy
	@echo "$(GREEN)Installation sécurisée terminée !$(NC)"
	@echo "$(YELLOW)Accès : https://localhost$(NC)"

# Génération des secrets
generate-secrets: ## Générer tous les secrets sécurisés
	@echo "$(YELLOW)Génération des secrets...$(NC)"
	chmod +x scripts/generate-secrets.sh
	./scripts/generate-secrets.sh

# Initialisation sécurisée de la base de données
init-db: ## Initialiser la base de données avec sécurité
	@echo "$(YELLOW)Initialisation sécurisée de la base de données...$(NC)"
	chmod +x scripts/init-secure-db.sh
	./scripts/init-secure-db.sh

# Nettoyage complet
purge: ## Suppression complète (DANGER)
	@echo "$(RED)ATTENTION: Cette action va tout supprimer !$(NC)"
	@read -p "Êtes-vous sûr ? (y/N) " -n 1 -r; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		$(DOCKER_COMPOSE) down --volumes --remove-orphans; \
		docker system prune -af; \
		$(CARGO) clean; \
		rm -rf nginx/ssl/*.pem; \
		rm -rf dist/; \
		echo "$(GREEN)Nettoyage complet terminé$(NC)"; \
	fi
