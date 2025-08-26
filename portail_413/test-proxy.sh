#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de test du proxy reverse
# Teste la connectivité et les redirections

echo "🧪 DCOP (413) - Test du proxy reverse"
echo "===================================="

echo "📊 Statut des conteneurs..."
docker-compose ps

echo ""
echo "🔍 Test de connectivité interne..."

# Tester la connectivité de nginx vers l'app
echo "1. Test proxy nginx -> app"
docker exec dcop_nginx wget --timeout=10 --tries=3 -q --spider http://dcop_app:8443/health 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ Nginx peut atteindre l'application"
else
    echo "   ❌ Nginx ne peut pas atteindre l'application"
fi

# Tester l'accès externe HTTP (redirection)
echo ""
echo "2. Test redirection HTTP -> HTTPS"
HTTP_RESPONSE=$(curl --max-time 10 --retry 3 -I -s -L http://localhost 2>/dev/null | head -1)
echo "   Response: "${HTTP_RESPONSE}""

# Tester l'accès HTTPS
echo ""
echo "3. Test accès HTTPS direct"
HTTPS_RESPONSE=$(curl --max-time 10 --retry 3 -I -s -k https://localhost 2>/dev/null | head -1)
echo "   Response: "${HTTPS_RESPONSE}""

echo ""
echo "🔍 Vérification des logs récents..."
echo "Nginx errors:"
docker-compose logs nginx 2>/dev/null | grep -i error | tail -3

echo ""
echo "Nginx warnings:"
docker-compose logs nginx 2>/dev/null | grep -i warn | tail -3

echo ""
echo "📈 Résumé des tests:"
echo "- Port 80 (HTTP): $(curl --max-time 10 --retry 3 -s -o /dev/null -w '%{http_code}' http://localhost 2>/dev/null || echo 'FAIL')"
echo "- Port 443 (HTTPS): $(curl --max-time 10 --retry 3 -s -o /dev/null -w '%{http_code}' -k https://localhost 2>/dev/null || echo 'FAIL')"

echo ""
echo "🌐 URLs à tester:"
echo "   • http://localhost (doit rediriger vers HTTPS)"
echo "   • https://localhost (doit afficher l'application)"
