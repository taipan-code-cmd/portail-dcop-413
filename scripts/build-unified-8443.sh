#!/bin/bash
# DCOP (413) - Script de construction architecture unifiée port 8443
# Frontend + Backend sur un seul port

set -e

echo "🎯 DCOP (413) - Architecture Unifiée Port 8443"
echo "============================================="

# Étape 1: Arrêter nginx (plus nécessaire)
echo "🛑 Arrêt des services non nécessaires..."
if docker ps | grep -q dcop_nginx; then
    docker stop dcop_nginx
    echo "✅ Nginx arrêté"
else
    echo "ℹ️  Nginx déjà arrêté"
fi

# Étape 2: Reconstruire le conteneur avec frontend intégré
echo "🔨 Construction du conteneur avec frontend intégré..."
cd /home/taipan_51/portail_413/portail_413

# Arrêter l'ancien conteneur
docker-compose stop dcop_app

# Reconstruire l'image
docker-compose build --no-cache dcop_app

# Redémarrer avec la nouvelle image
docker-compose up -d dcop_app

echo "⏳ Attente du démarrage du conteneur..."
sleep 10

# Étape 3: Tester l'accès
echo "🔍 Test de l'application unifiée..."

# Test du backend/API
API_STATUS=$(curl --max-time 10 --retry 3 -s -o /dev/null -w "%{http_code}" http://localhost:8443/health 2>/dev/null || echo "000")
if [ "${API_STATUS}"" = "200" ]; then
    echo "✅ API Backend accessible (8443/health)"
else
    echo "❌ API Backend: Status "${API_STATUS}""
fi

# Test des fichiers statiques
STATIC_STATUS=$(curl --max-time 10 --retry 3 -s -o /dev/null -w "%{http_code}" http://localhost:8443/static/ 2>/dev/null || echo "000")
if [ "${STATIC_STATUS}"" = "200" ] || [ "${STATIC_STATUS}"" = "301" ] || [ "${STATIC_STATUS}"" = "302" ]; then
    echo "✅ Fichiers statiques accessibles (8443/static/)"
else
    echo "❌ Fichiers statiques: Status "${STATIC_STATUS}""
fi

# Étape 4: Appliquer la sécurité des ports
echo "🔒 Application de la sécurité des ports..."
/home/taipan_51/portail_413/scripts/port-security.sh status

# Étape 5: Afficher le résumé
echo ""
echo "🎯 ARCHITECTURE FINALE:"
echo "======================"
echo "📱 Frontend WASM: http://localhost:8443/static/"
echo "🦀 Backend API: http://localhost:8443/api/"
echo "🏠 Application complète: http://localhost:8443/"
echo ""
echo "✅ UN SEUL PORT POUR TOUT: 8443"
echo "✅ Plus de confusion frontend/backend"
echo "✅ Plus simple à maintenir"
echo "✅ Plus sécurisé (surface d'attaque réduite)"
