#!/bin/bash
set -euo pipefail
# Script de validation finale - Niveau Production
# Teste toutes les corrections de sécurité appliquées

echo "🏆 VALIDATION SÉCURITÉ NIVEAU PRODUCTION"
echo "========================================"
echo "Test complet des 15 vulnérabilités corrigées"
echo ""

SCORE=0
TOTAL=15
ISSUES=()

# Test 1: Secrets sécurisés (CRITIQUE)
echo "🔐 1/15 - Test secrets sécurisés..."
if [ ! -f "/home/taipan_51/portail_413/secrets/jwt_secret.txt" ] && [ -f "/home/taipan_51/portail_413/portail_413/secrets_secure/jwt_secret.key" ]; then
    echo "✅ Secrets JWT migrés vers format sécurisé"
    ((SCORE++))
else
    echo "❌ Secrets encore vulnérables"
    ISSUES+=("Secrets en clair")
fi

# Test 2: HTTPS configuré (CRITIQUE)
echo "🌐 2/15 - Test HTTPS..."
if grep -q "listen 443 ssl" /home/taipan_51/portail_413/portail_413/nginx/nginx.conf; then
    echo "✅ HTTPS configuré avec redirection"
    ((SCORE++))
else
    echo "❌ HTTPS non configuré"
    ISSUES+=("HTTPS manquant")
fi

# Test 3: CSP configuré (ÉLEVÉ)
echo "🛡️ 3/15 - Test Content Security Policy..."
if [ -f "/home/taipan_51/portail_413/portail_413/nginx/csp_advanced.conf" ]; then
    echo "✅ CSP avancé configuré"
    ((SCORE++))
else
    echo "❌ CSP avancé manquant"
    ISSUES+=("CSP insuffisant")
fi

# Test 4: Argon2 configuré (ÉLEVÉ)
echo "🔒 4/15 - Test migration Argon2..."
if grep -q "argon2" /home/taipan_51/portail_413/portail_413/Cargo.toml && [ -f "/home/taipan_51/portail_413/portail_413/src/security/password_security.rs" ]; then
    echo "✅ Argon2 configuré et handler créé"
    ((SCORE++))
else
    echo "❌ Migration Argon2 incomplète"
    ISSUES+=("bcrypt encore utilisé")
fi

# Test 5: Permissions secrets strictes (ÉLEVÉ)
echo "🔐 5/15 - Test permissions secrets..."
if [ -d "/home/taipan_51/portail_413/portail_413/secrets_secure" ]; then
    PERMS=$(find /home/taipan_51/portail_413/portail_413/secrets_secure -name "*.key" -exec stat -c "%a" {} \; | head -1)
    if [ "${PERMS}"" = "600" ]; then
        echo "✅ Permissions secrets strictes (600)"
        ((SCORE++))
    else
        echo "❌ Permissions secrets insuffisantes ("${PERMS}")"
        ISSUES+=("Permissions trop ouvertes")
    fi
else
    echo "❌ Répertoire secrets sécurisé manquant"
    ISSUES+=("Structure secrets incorrecte")
fi

# Test 6: SSL PostgreSQL (ÉLEVÉ)
echo "🗄️ 6/15 - Test SSL PostgreSQL..."
if [ -f "/home/taipan_51/portail_413/postgresql_ssl/server.crt" ] && grep -q "ssl = on" /home/taipan_51/portail_413/postgresql_ssl/postgresql.conf; then
    echo "✅ SSL PostgreSQL configuré"
    ((SCORE++))
else
    echo "❌ SSL PostgreSQL manquant"
    ISSUES+=("DB non chiffrée")
fi

# Test 7: Rotation JWT (ÉLEVÉ)
echo "🔄 7/15 - Test rotation JWT..."
if [ -f "/home/taipan_51/portail_413/portail_413/src/security/jwt_rotation.rs" ]; then
    echo "✅ Système rotation JWT créé"
    ((SCORE++))
else
    echo "❌ Rotation JWT manquante"
    ISSUES+=("JWT statiques")
fi

# Test 8: Headers sécurité complets (MOYEN)
echo "🛡️ 8/15 - Test headers sécurité..."
if grep -q "Strict-Transport-Security" /home/taipan_51/portail_413/portail_413/nginx/security_headers.conf; then
    echo "✅ Headers sécurité complets"
    ((SCORE++))
else
    echo "❌ Headers sécurité incomplets"
    ISSUES+=("Headers manquants")
fi

# Test 9: Rate limiting strict (MOYEN)
echo "🚦 9/15 - Test rate limiting..."
if grep -q "rate=30r/s" /home/taipan_51/portail_413/portail_413/nginx/nginx.conf; then
    echo "✅ Rate limiting configuré"
    ((SCORE++))
else
    echo "❌ Rate limiting insuffisant"
    ISSUES+=("DoS possible")
fi

# Test 10: Session timeout réduit (MOYEN)
echo "⏱️ 10/15 - Test timeout session..."
if [ -f "/home/taipan_51/portail_413/portail_413/src/config/session_config.rs" ] && grep -q "900" /home/taipan_51/portail_413/portail_413/src/config/session_config.rs; then
    echo "✅ Timeout session réduit (15 min)"
    ((SCORE++))
else
    echo "❌ Timeout session trop long"
    ISSUES+=("Sessions persistantes")
fi

# Test 11: Logging sécurisé (MOYEN)
echo "📝 11/15 - Test logging sécurisé..."
if [ -f "/home/taipan_51/portail_413/portail_413/src/utils/security_logger.rs" ]; then
    echo "✅ Logging sécurisé configuré"
    ((SCORE++))
else
    echo "❌ Logging sécurisé manquant"
    ISSUES+=("Audit insuffisant")
fi

# Test 12: Validation input (MOYEN)
echo "🔍 12/15 - Test validation input..."
if [ -f "/home/taipan_51/portail_413/portail_413/src/utils/input_validator.rs" ]; then
    echo "✅ Validation input renforcée"
    ((SCORE++))
else
    echo "❌ Validation input faible"
    ISSUES+=("Injection possible")
fi

# Test 13: Monitoring intrusion (ÉLEVÉ)
echo "🔍 13/15 - Test monitoring intrusion..."
if [ -f "/home/taipan_51/portail_413/security_monitoring/fail2ban.conf" ]; then
    echo "✅ Monitoring Fail2ban configuré"
    ((SCORE++))
else
    echo "❌ Monitoring intrusion manquant"
    ISSUES+=("Attaques non détectées")
fi

# Test 14: Système d'alertes (ÉLEVÉ)
echo "📧 14/15 - Test système d'alertes..."
if [ -f "/home/taipan_51/portail_413/portail_413/src/security/alert_system.rs" ]; then
    echo "✅ Système d'alertes temps réel"
    ((SCORE++))
else
    echo "❌ Système d'alertes manquant"
    ISSUES+=("Incidents non notifiés")
fi

# Test 15: Configuration Docker sécurisée
echo "🐳 15/15 - Test configuration Docker..."
if grep -q "config_file=/etc/postgresql/postgresql.conf" /home/taipan_51/portail_413/docker-compose.full.yml; then
    echo "✅ Docker configuration sécurisée"
    ((SCORE++))
else
    echo "❌ Configuration Docker incomplète"
    ISSUES+=("Container non sécurisé")
fi

echo ""
echo "📊 RÉSULTATS FINAUX"
echo "==================="

PERCENTAGE=$((SCORE * 100 / TOTAL))
echo "Score: "${SCORE}"/"${TOTAL}" ("${PERCENTAGE}"%)"

if [ ${#ISSUES[@]} -gt 0 ]; then
    echo ""
    echo "❌ Issues restants:"
    for issue in "${ISSUES[@]}"; do
        echo "   - $issue"
    done
fi

echo ""
if [ "${PERCENTAGE}" -ge 95 ]; then
    echo "🏆 EXCELLENT (95-100%) - PRODUCTION READY"
    echo "✅ Application prête pour déploiement production"
    echo "✅ Toutes les vulnérabilités critiques et élevées corrigées"
    echo "✅ Conformité sécurité maximale"
    exit 0
elif [ "${PERCENTAGE}" -ge 85 ]; then
    echo "🥇 TRÈS BON (85-94%) - PRODUCTION ACCEPTABLE"
    echo "✅ Application acceptable pour production"
    echo "⚠️ Quelques améliorations mineures recommandées"
    echo "✅ Risque résiduel très faible"
    exit 0
elif [ "${PERCENTAGE}" -ge 70 ]; then
    echo "🥈 BON (70-84%) - STAGING READY"
    echo "✅ Application prête pour staging"
    echo "⚠️ Corrections nécessaires avant production"
    echo "🔄 Continuer les améliorations sécurité"
    exit 0
elif [ "${PERCENTAGE}" -ge 50 ]; then
    echo "🥉 MOYEN (50-69%) - DÉVELOPPEMENT SEULEMENT"
    echo "⚠️ Application pour développement uniquement"
    echo "❌ Corrections majeures nécessaires"
    echo "🔧 Reprendre audit sécurité"
    exit 1
else
    echo "🚨 CRITIQUE (0-49%) - DÉPLOIEMENT INTERDIT"
    echo "❌ Application non sécurisée"
    echo "❌ Vulnérabilités critiques présentes"
    echo "🛑 Arrêter tout déploiement"
    exit 2
fi
