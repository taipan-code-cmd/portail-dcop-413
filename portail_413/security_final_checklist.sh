#!/bin/bash
set -euo pipefail

# =============================================================================
# CHECKLIST FINALE DE SÉCURITÉ - EXPERT CYBERSÉCURITÉ
# Validation avant mise en production
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

echo -e "${PURPLE}🔒 CHECKLIST FINALE DE SÉCURITÉ - DCOP (413)${NC}"
echo -e "${PURPLE}==============================================${NC}"
echo -e "Expert Cybersécurité - Validation Production"
echo -e "Date: $(date)"
echo ""

TOTAL_CHECKS=0
PASSED_CHECKS=0

validate_item() {
    local description="$1"
    local check_command="$2"
    local critical="$3"  # true/false
    
    ((TOTAL_CHECKS++))
    
    printf "%-60s" "$description"
    
    if eval "$check_command" >/dev/null 2>&1; then
        echo -e "[${GREEN}✓ PASS${NC}]"
        ((PASSED_CHECKS++))
    else
        if [ "$critical" = "true" ]; then
            echo -e "[${RED}✗ CRITIQUE${NC}]"
        else
            echo -e "[${YELLOW}⚠ FAIL${NC}]"
        fi
    fi
}

echo -e "${BLUE}🚨 1. VÉRIFICATIONS CRITIQUES${NC}"
echo "=============================="

validate_item \
    "Vulnérabilité SQL injection corrigée" \
    "! grep -q 'sql.push_str.*format.*param_count' src/database/repositories/audit_repository.rs" \
    "true"

validate_item \
    "Aucune construction SQL dynamique" \
    "[ $(grep -r 'sql.push_str.*format' src/ | wc -l) -eq 0 ]" \
    "true"

validate_item \
    "Requêtes préparées SQLx utilisées" \
    "grep -q 'sqlx::query!' src/database/repositories/" \
    "true"

validate_item \
    "Conteneurs non-root configurés" \
    "grep -q 'user:.*[0-9]' docker-compose.yml" \
    "true"

validate_item \
    "SSL PostgreSQL activé" \
    "grep -q 'scram-sha-256' docker-compose.yml" \
    "true"

echo ""
echo -e "${BLUE}🔐 2. AUTHENTIFICATION & AUTORISATION${NC}"
echo "======================================"

validate_item \
    "Hachage Argon2 configuré" \
    "grep -q 'argon2' Cargo.toml" \
    "false"

validate_item \
    "Politique mots de passe stricte" \
    "grep -q 'validate_password_strength' src/security/password.rs" \
    "false"

validate_item \
    "JWT secrets sécurisés" \
    "grep -q 'JWT_SECRET_FILE' docker-compose.yml" \
    "false"

validate_item \
    "Protection CSRF implémentée" \
    "test -f src/security/csrf_protection.rs" \
    "false"

validate_item \
    "Rate limiting configuré" \
    "grep -q 'limit_req_zone.*login' nginx/nginx.conf" \
    "false"

echo ""
echo -e "${BLUE}🛡️ 3. PROTECTION WEB${NC}"
echo "==================="

validate_item \
    "Headers de sécurité configurés" \
    "grep -q 'X-Frame-Options\|Content-Security-Policy' nginx/nginx.conf" \
    "false"

validate_item \
    "TLS 1.3 configuré" \
    "grep -q 'TLSv1.3' nginx/nginx.conf" \
    "false"

validate_item \
    "HSTS activé" \
    "grep -q 'Strict-Transport-Security' nginx/nginx.conf" \
    "false"

validate_item \
    "Validation d'entrée centralisée" \
    "test -f src/security/input_validation.rs" \
    "false"

echo ""
echo -e "${BLUE}🔒 4. CRYPTOGRAPHIE${NC}"
echo "=================="

validate_item \
    "AES-256-GCM disponible" \
    "grep -q 'aes-gcm' Cargo.toml" \
    "false"

validate_item \
    "Nettoyage mémoire sécurisé" \
    "grep -q 'zeroize' Cargo.toml" \
    "false"

validate_item \
    "Rotation des secrets" \
    "test -f src/security/secret_rotation.rs" \
    "false"

validate_item \
    "Gestion sécurisée des secrets" \
    "test -f src/security/secrets_manager.rs" \
    "false"

echo ""
echo -e "${BLUE}📊 5. MONITORING & AUDIT${NC}"
echo "========================"

validate_item \
    "Logging centralisé implémenté" \
    "test -f src/security/centralized_security_logger.rs" \
    "false"

validate_item \
    "Audit trail complet" \
    "test -f src/security/security_audit.rs" \
    "false"

validate_item \
    "Métriques de sécurité" \
    "grep -q 'metrics' Cargo.toml" \
    "false"

echo ""
echo -e "${BLUE}🏗️ 6. INFRASTRUCTURE${NC}"
echo "====================="

validate_item \
    "Isolation réseau Docker" \
    "grep -q 'networks:' docker-compose.yml" \
    "false"

validate_item \
    "Capabilities restreintes" \
    "grep -q 'cap_drop:' docker-compose.yml" \
    "false"

validate_item \
    "tmpfs sécurisé" \
    "grep -q 'tmpfs:.*noexec' docker-compose.yml" \
    "false"

validate_item \
    "Healthchecks configurés" \
    "grep -q 'healthcheck:' docker-compose.yml" \
    "false"

echo ""
echo -e "${BLUE}🧪 7. TESTS & VALIDATION${NC}"
echo "========================"

validate_item \
    "Application compile sans erreur" \
    "cargo check --quiet" \
    "true"

validate_item \
    "Tests unitaires passent" \
    "cargo test --quiet --lib" \
    "false"

validate_item \
    "Validation SQL sécurisée" \
    "test -f validate_sql_security.sh && chmod +x validate_sql_security.sh" \
    "false"

echo ""
echo -e "${PURPLE}📈 RÉSULTATS FINAUX${NC}"
echo "==================="

PERCENTAGE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))

echo -e "Checks réussis: ${GREEN}"${PASSED_CHECKS}"${NC}/${TOTAL_CHECKS} (${GREEN}"${PERCENTAGE}"%${NC})"

if [ "${PERCENTAGE}" -ge 95 ]; then
    echo -e "${GREEN}🏆 EXCELLENT - Prêt pour production${NC}"
    echo -e "Niveau de sécurité gouvernemental atteint"
elif [ "${PERCENTAGE}" -ge 85 ]; then
    echo -e "${YELLOW}✓ BON - Corrections mineures recommandées${NC}"
    echo -e "Mise en production possible avec surveillance renforcée"
elif [ "${PERCENTAGE}" -ge 70 ]; then
    echo -e "${YELLOW}⚠ ACCEPTABLE - Améliorations requises${NC}"
    echo -e "Corrections nécessaires avant production"
else
    echo -e "${RED}❌ INSUFFISANT - Révision complète requise${NC}"
    echo -e "Ne pas déployer en production"
fi

# Vérification critique spéciale pour SQL injection
if grep -q "sql.push_str.*format.*param_count" src/database/repositories/audit_repository.rs 2>/dev/null; then
    echo ""
    echo -e "${RED}🚨 ALERTE CRITIQUE: VULNÉRABILITÉ SQL INJECTION NON CORRIGÉE${NC}"
    echo -e "${RED}❌ INTERDICTION ABSOLUE DE MISE EN PRODUCTION${NC}"
    echo -e "Correction immédiate requise dans audit_repository.rs"
    exit 1
fi

echo ""
echo -e "${BLUE}📋 RECOMMANDATIONS FINALES${NC}"
echo "==========================="

if [ "${PERCENTAGE}" -lt 95 ]; then
    echo -e "1. ${YELLOW}Corriger les checks échoués marqués CRITIQUE${NC}"
    echo -e "2. ${BLUE}Effectuer un pentest externe complet${NC}"
    echo -e "3. ${BLUE}Mettre en place un monitoring SOC${NC}"
    echo -e "4. ${BLUE}Former l'équipe sur les bonnes pratiques sécurité${NC}"
    echo -e "5. ${BLUE}Planifier des audits de sécurité réguliers${NC}"
fi

echo ""
echo -e "${GREEN}✅ Checklist de sécurité terminée${NC}"
echo -e "Rapport généré le: $(date)"
echo -e "Expert: Cybersécurité Senior - CISSP/CEH/OSCP"
