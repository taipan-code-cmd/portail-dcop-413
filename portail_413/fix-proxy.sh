#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de correction du proxy reverse
# Résout les problèmes de permissions Nginx et redémarre les services

echo "🔧 DCOP (413) - Correction du proxy reverse"
echo "=========================================="

# Arrêter tous les conteneurs
echo "📛 Arrêt des conteneurs..."
docker-compose down

# Nettoyer les volumes Nginx problématiques
echo "🧹 Nettoyage des volumes..."
docker volume rm portail_413_nginx_cache 2>/dev/null || true

# Reconstruire uniquement si nécessaire
echo "🔨 Reconstruction des images..."
docker-compose build --no-cache nginx

# Redémarrer les services dans l'ordre correct
echo "🚀 Redémarrage des services..."
docker-compose up -d postgres

# Attendre que PostgreSQL soit prêt
echo "⏳ Attente de PostgreSQL..."
sleep 10

docker-compose up -d dcop_app

# Attendre que l'application soit prête
echo "⏳ Attente de l'application..."
sleep 15

docker-compose up -d nginx

# Vérifier le statut
echo "📊 Statut des conteneurs..."
sleep 5
docker-compose ps

echo ""
echo "🔍 Logs Nginx (dernières lignes)..."
docker-compose logs --tail=10 nginx

echo ""
echo "✅ Correction terminée!"
echo "🌐 Testez l'accès : https://localhost"
echo "📋 Logs complets : docker-compose logs -f nginx"
