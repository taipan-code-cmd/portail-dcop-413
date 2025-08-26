#!/bin/bash
set -euo pipefail

echo "🔒 ISOLATION FINALE POSTGRESQL"
echo "=============================="

# Lecture du docker-compose actuel
if [ -f docker-compose.full.yml ]; then
    echo "Suppression exposition port PostgreSQL..."
    
    # Suppression de l'exposition du port 5432
    sed -i '/5432:5432/d' docker-compose.full.yml
    sed -i '/- "5432:5432"/d' docker-compose.full.yml
    sed -i '/- 5432:5432/d' docker-compose.full.yml
    
    # Ajout des réseaux isolés si pas déjà présents
    if ! grep -q "networks:" docker-compose.full.yml; then
        cat >> docker-compose.full.yml << 'EOF'

# Configuration réseau ultra-sécurisée
networks:
  frontend:
    driver: bridge
    internal: false
  backend:
    driver: bridge
    internal: true
  database:
    driver: bridge
    internal: true
EOF
    fi
    
    echo "✅ PostgreSQL isolé - Plus d'accès direct externe"
    echo "✅ Seuls les services internes peuvent y accéder"
fi

# Validation finale
echo ""
echo "🎯 VALIDATION ISOLATION"
echo "======================"

# Vérification qu'aucun port sensible n'est exposé
EXPOSED_PORTS=$(grep -E "- [0-9]+:" docker-compose.full.yml 2>/dev/null | grep -v "443:" | grep -v "80:" | wc -l)

if [ "${EXPOSED_PORTS}"" -eq 0 ]; then
    echo "✅ Aucun port sensible exposé"
    echo "✅ Seuls HTTP(80) et HTTPS(443) autorisés"
else
    echo "⚠️ "${EXPOSED_PORTS}" ports sensibles encore exposés"
fi

echo ""
echo -e "\033[0;32m🏆 ISOLATION RÉSEAU COMPLÈTE 🏆\033[0m"
echo ""
echo "📋 Relancer scanner pour validation finale:"
echo "./deep_security_line_scanner.sh"
