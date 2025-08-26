#!/bin/bash
set -euo pipefail
# Script de redémarrage propre avec configuration dcop_user

echo "=== DCOP (413) - Redémarrage propre ==="
echo "Date: $(date)"
echo

# Arrêter tous les services existants
echo "1. Arrêt des services..."
docker-compose down --volumes --remove-orphans 2>/dev/null || true
docker stop $(docker ps -aq) 2>/dev/null || true

# Nettoyer les caches et volumes
echo "2. Nettoyage des volumes..."
docker volume prune -f
docker network prune -f

# Vérifier les fichiers de configuration
echo "3. Vérification de la configuration..."
echo "DATABASE_URL dans .env.dev:"
grep "DATABASE_URL" .env.dev
echo

echo "POSTGRES_USER dans docker-compose.yml:"
grep "POSTGRES_USER" docker-compose.yml
echo

# Définir les variables d'environnement explicitement
export SERVER_HOST=0.0.0.0
export SERVER_PORT=8443
export DATABASE_URL="postgresql://dcop_user:EhbcQDl6bcvRPvEgFtr2O6cOuQdAuTMmpO3XkLNMqMw=@localhost:5433/dcop_413"
export JWT_SECRET="dev_jwt_secret_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
export ENCRYPTION_KEY="dev_encryption_key_1234567890abcdef1234567890abcdef1234567890abcdef123456789abc"
export SECURITY_SALT="dev_salt_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123"
export LOG_LEVEL=info
export RUST_LOG="portail_413=info,actix_web=info"

echo "4. Variables d'environnement définies:"
echo "DATABASE_URL: "${DATABASE_URL}""
echo "SERVER_PORT: "${SERVER_PORT}""
echo

# Redémarrer les services
echo "5. Redémarrage des services Docker..."
docker-compose up -d

echo "6. Attente de la stabilisation..."
sleep 10

# Vérifier l'état des services
echo "7. État des services:"
docker-compose ps

echo "8. Logs PostgreSQL récents:"
docker logs dcop_postgres_secure --tail 5

echo
echo "=== Redémarrage terminé ==="
echo "Application disponible sur: https://localhost:8443"
