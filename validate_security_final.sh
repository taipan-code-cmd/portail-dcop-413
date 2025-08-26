#!/bin/bash
set -euo pipefail
echo "🔍 VALIDATION SÉCURITÉ FINALE"
echo "=============================="

SCORE=0
TOTAL=15

# Test 1: Secrets sécurisés
if [ ! -f "/home/taipan_51/portail_413/secrets/jwt_secret.txt" ]; then
    echo "✅ Secrets JWT sécurisés"
    ((SCORE++))
else
    echo "❌ Secrets JWT encore en clair"
fi

# Test 2: HTTPS configuré
if grep -q "listen 443 ssl" /home/taipan_51/portail_413/portail_413/nginx/nginx.conf; then
    echo "✅ HTTPS configuré"
    ((SCORE++))
else
    echo "❌ HTTPS non configuré"
fi

# Test 3: CSP configuré
if grep -q "Content-Security-Policy" /home/taipan_51/portail_413/portail_413/nginx/security_headers.conf; then
    echo "✅ CSP configuré"
    ((SCORE++))
else
    echo "❌ CSP non configuré"
fi

# Test 4: Argon2 configuré
if grep -q "argon2" /home/taipan_51/portail_413/portail_413/Cargo.toml; then
    echo "✅ Argon2 configuré"
    ((SCORE++))
else
    echo "❌ Argon2 non configuré"
fi

# Test 5: Permissions strictes
SECRET_PERMS=$(stat -c "%a" /home/taipan_51/portail_413/portail_413/secrets_secure/*.key 2>/dev/null | head -1)
if [ "${SECRET_PERMS}"" = "600" ]; then
    echo "✅ Permissions secrets strictes"
    ((SCORE++))
else
    echo "❌ Permissions secrets insuffisantes"
fi

# Calcul score final
PERCENTAGE=$((SCORE * 100 / TOTAL))
echo ""
echo "📊 SCORE FINAL: "${SCORE}"/"${TOTAL}" ("${PERCENTAGE}"%)"

if [ "${PERCENTAGE}" -ge 95 ]; then
    echo "🏆 EXCELLENT - Prêt pour production"
    exit 0
elif [ "${PERCENTAGE}" -ge 80 ]; then
    echo "✅ BON - Quelques améliorations mineures"
    exit 0
elif [ "${PERCENTAGE}" -ge 60 ]; then
    echo "⚠️ MOYEN - Corrections nécessaires"
    exit 1
else
    echo "🚨 CRITIQUE - Déploiement interdit"
    exit 2
fi
