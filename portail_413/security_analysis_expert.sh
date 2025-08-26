#!/bin/bash
set -euo pipefail

# =============================================================================
# ANALYSE DE SÉCURITÉ APPROFONDIE - EXPERT CYBERSÉCURITÉ
# Évaluation Security by Design pour DCOP (413) Portail des Visites
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔒 ANALYSE DE SÉCURITÉ APPROFONDIE - DCOP (413)${NC}"
echo -e "${BLUE}=============================================${NC}"
echo -e "Expert Cybersécurité - Approche Security by Design"
echo -e "Date: $(date)"
echo ""

# Variables
SECURITY_SCORE=0
TOTAL_CHECKS=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

check_security_item() {
    local description="$1"
    local check_command="$2"
    local severity="$3"  # CRITICAL, HIGH, MEDIUM, LOW
    local recommendation="$4"
    
    ((TOTAL_CHECKS++))
    
    if eval "$check_command" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $description"
        ((SECURITY_SCORE++))
    else
        case $severity in
            "CRITICAL")
                echo -e "  ${RED}✗ CRITIQUE:${NC} $description"
                echo -e "    ${RED}➤${NC} $recommendation"
                ((CRITICAL_ISSUES++))
                ;;
            "HIGH")
                echo -e "  ${RED}✗ ÉLEVÉ:${NC} $description"
                echo -e "    ${YELLOW}➤${NC} $recommendation"
                ((HIGH_ISSUES++))
                ;;
            "MEDIUM")
                echo -e "  ${YELLOW}⚠ MOYEN:${NC} $description"
                echo -e "    ${YELLOW}➤${NC} $recommendation"
                ((MEDIUM_ISSUES++))
                ;;
            "LOW")
                echo -e "  ${YELLOW}! FAIBLE:${NC} $description"
                echo -e "    ${BLUE}➤${NC} $recommendation"
                ((LOW_ISSUES++))
                ;;
        esac
    fi
}

echo -e "${PURPLE}🏗️  1. ARCHITECTURE & DÉFENSE EN PROFONDEUR${NC}"
echo "================================================"

check_security_item \
    "Isolation réseau par conteneurs Docker" \
    "grep -q 'networks:' docker-compose.yml" \
    "HIGH" \
    "Implémenter l'isolation réseau avec des subnets dédiés"

check_security_item \
    "Proxy reverse Nginx configuré" \
    "test -f nginx/nginx.conf" \
    "HIGH" \
    "Configurer un proxy reverse pour masquer l'application"

check_security_item \
    "Utilisateurs non-root dans les conteneurs" \
    "grep -q 'USER.*[^r]oot' Dockerfile" \
    "CRITICAL" \
    "Créer et utiliser des utilisateurs non-root dans tous les conteneurs"

check_security_item \
    "Capabilities Linux restreintes" \
    "grep -q 'cap_drop:' docker-compose.yml" \
    "HIGH" \
    "Implémenter le principe du moindre privilège avec cap_drop/cap_add"

check_security_item \
    "Volumes tmpfs avec options sécurisées" \
    "grep -q 'tmpfs:.*noexec' docker-compose.yml" \
    "MEDIUM" \
    "Configurer tmpfs avec noexec,nosuid pour prévenir l'exécution de code"

echo ""
echo -e "${PURPLE}🔐 2. AUTHENTIFICATION & GESTION DES SESSIONS${NC}"
echo "============================================="

check_security_item \
    "Hachage Argon2 pour les mots de passe" \
    "grep -r 'argon2' Cargo.toml" \
    "CRITICAL" \
    "Migrer vers Argon2id pour le hachage des mots de passe"

check_security_item \
    "Politique de mots de passe robuste" \
    "grep -q 'validate_password_strength' src/security/password.rs" \
    "HIGH" \
    "Implémenter une validation stricte des mots de passe (14+ chars, complexité)"

check_security_item \
    "JWT avec secrets sécurisés" \
    "grep -q 'JWT_SECRET_FILE' docker-compose.yml" \
    "CRITICAL" \
    "Utiliser des secrets Docker pour les clés JWT"

check_security_item \
    "Gestion de session sécurisée" \
    "test -f src/security/session_management.rs" \
    "HIGH" \
    "Implémenter une gestion de session avec expiration et rotation"

check_security_item \
    "Rate limiting sur authentification" \
    "grep -q 'limit_req_zone.*login' nginx/nginx.conf" \
    "HIGH" \
    "Configurer un rate limiting strict sur les endpoints d'authentification"

echo ""
echo -e "${PURPLE}🛡️  3. PROTECTION WEB (OWASP TOP 10)${NC}"
echo "====================================="

check_security_item \
    "Protection CSRF implémentée" \
    "test -f src/security/csrf_protection.rs" \
    "CRITICAL" \
    "Implémenter la protection CSRF avec double submit cookies"

check_security_item \
    "Validation d'entrée centralisée" \
    "test -f src/security/input_validation.rs" \
    "CRITICAL" \
    "Centraliser la validation et sanitisation des entrées utilisateur"

check_security_item \
    "Headers de sécurité configurés" \
    "grep -q 'X-Frame-Options\\|Content-Security-Policy' nginx/nginx.conf" \
    "HIGH" \
    "Configurer tous les headers de sécurité (CSP, X-Frame-Options, etc.)"

check_security_item \
    "Protection XSS dans les templates" \
    "grep -q 'XSS' src/security/" \
    "HIGH" \
    "Implémenter l'échappement automatique dans les templates"

check_security_item \
    "Requêtes SQL préparées (SQLx)" \
    "grep -q 'sqlx::query!' src/" \
    "CRITICAL" \
    "Utiliser exclusivement des requêtes préparées pour prévenir l'injection SQL"

echo ""
echo -e "${PURPLE}🔒 4. CHIFFREMENT & CRYPTOGRAPHIE${NC}"
echo "=================================="

check_security_item \
    "TLS 1.3 configuré" \
    "grep -q 'ssl_protocols.*TLSv1.3' nginx/nginx.conf" \
    "HIGH" \
    "Configurer TLS 1.3 minimum avec des ciphers sécurisés"

check_security_item \
    "Chiffrement AES-256-GCM" \
    "grep -q 'aes-gcm' Cargo.toml" \
    "HIGH" \
    "Utiliser AES-256-GCM pour le chiffrement symétrique"

check_security_item \
    "Gestion sécurisée des secrets" \
    "test -f src/security/secrets_manager.rs" \
    "CRITICAL" \
    "Implémenter un gestionnaire de secrets avec rotation automatique"

check_security_item \
    "HSTS configuré" \
    "grep -q 'Strict-Transport-Security' nginx/nginx.conf" \
    "MEDIUM" \
    "Activer HSTS pour forcer HTTPS"

echo ""
echo -e "${PURPLE}📊 5. MONITORING & AUDIT${NC}"
echo "========================"

check_security_item \
    "Logging de sécurité centralisé" \
    "test -f src/security/centralized_security_logger.rs" \
    "HIGH" \
    "Implémenter un logging de sécurité centralisé avec corrélation"

check_security_item \
    "Audit trail complet" \
    "test -f src/security/security_audit.rs" \
    "HIGH" \
    "Enregistrer toutes les actions sensibles avec horodatage"

check_security_item \
    "Détection d'intrusion" \
    "grep -q 'suspicious' src/security/" \
    "MEDIUM" \
    "Implémenter la détection de patterns suspects"

check_security_item \
    "Métriques de sécurité" \
    "grep -q 'metrics' Cargo.toml" \
    "MEDIUM" \
    "Exposer des métriques de sécurité pour monitoring"

echo ""
echo -e "${PURPLE}🚨 6. PROTECTION DDOS & RESILIENCE${NC}"
echo "=================================="

check_security_item \
    "Rate limiting multi-niveaux" \
    "grep -c 'limit_req_zone' nginx/nginx.conf | grep -q '[5-9]'" \
    "HIGH" \
    "Configurer des zones de rate limiting différenciées"

check_security_item \
    "Protection contre slow HTTP attacks" \
    "grep -q 'client_body_timeout\\|client_header_timeout' nginx/nginx.conf" \
    "MEDIUM" \
    "Configurer des timeouts courts pour prévenir les attaques lentes"

check_security_item \
    "Limitation de la taille des requêtes" \
    "grep -q 'client_max_body_size' nginx/nginx.conf" \
    "MEDIUM" \
    "Limiter la taille des uploads pour prévenir l'épuisement de ressources"

check_security_item \
    "Healthchecks configurés" \
    "grep -q 'healthcheck:' docker-compose.yml" \
    "LOW" \
    "Configurer des healthchecks pour détecter les défaillances"

echo ""
echo -e "${PURPLE}🔍 7. SÉCURITÉ DES DONNÉES${NC}"
echo "=========================="

check_security_item \
    "Chiffrement de la base de données" \
    "grep -q 'sslmode=require' src/" \
    "HIGH" \
    "Activer le chiffrement TLS pour PostgreSQL"

check_security_item \
    "Rotation des clés de chiffrement" \
    "test -f src/security/secret_rotation.rs" \
    "MEDIUM" \
    "Implémenter la rotation automatique des clés"

check_security_item \
    "Nettoyage sécurisé de la mémoire" \
    "grep -q 'zeroize' Cargo.toml" \
    "MEDIUM" \
    "Utiliser zeroize pour nettoyer les données sensibles en mémoire"

check_security_item \
    "Validation des données en sortie" \
    "grep -q 'output.*encoding\\|sanitiz' src/" \
    "HIGH" \
    "Valider et encoder toutes les données en sortie"

echo ""
echo -e "${BLUE}📈 RÉSULTATS DE L'ANALYSE${NC}"
echo "========================="

SECURITY_PERCENTAGE=$((SECURITY_SCORE * 100 / TOTAL_CHECKS))

echo -e "Score de sécurité: ${GREEN}"${SECURITY_SCORE}"${NC}/${BLUE}"${TOTAL_CHECKS}"${NC} (${GREEN}"${SECURITY_PERCENTAGE}"%${NC})"
echo -e "Issues critiques: ${RED}"${CRITICAL_ISSUES}"${NC}"
echo -e "Issues élevés: ${YELLOW}"${HIGH_ISSUES}"${NC}"
echo -e "Issues moyens: ${YELLOW}"${MEDIUM_ISSUES}"${NC}"
echo -e "Issues faibles: "${LOW_ISSUES}""

echo ""
echo -e "${PURPLE}🎯 ÉVALUATION GLOBALE${NC}"
echo "===================="

if [ "${SECURITY_PERCENTAGE}" -ge 90 ]; then
    echo -e "${GREEN}🏆 EXCELLENT${NC} - Application très sécurisée"
    echo -e "Conforme aux standards OWASP et Security by Design"
elif [ "${SECURITY_PERCENTAGE}" -ge 75 ]; then
    echo -e "${YELLOW}✓ BON${NC} - Niveau de sécurité satisfaisant"
    echo -e "Quelques améliorations recommandées"
elif [ "${SECURITY_PERCENTAGE}" -ge 60 ]; then
    echo -e "${YELLOW}⚠ ACCEPTABLE${NC} - Sécurité de base présente"
    echo -e "Corrections nécessaires avant production"
else
    echo -e "${RED}❌ INSUFFISANT${NC} - Risques de sécurité importants"
    echo -e "Révision complète requise"
fi

if [ "${CRITICAL_ISSUES}" -gt 0 ]; then
    echo -e "${RED}⚠️  ATTENTION: "${CRITICAL_ISSUES}" issue(s) critique(s) détecté(s)${NC}"
    echo -e "Correction immédiate requise avant déploiement"
fi

echo ""
echo -e "${BLUE}📋 RECOMMANDATIONS PRIORITAIRES${NC}"
echo "================================"

if [ "${CRITICAL_ISSUES}" -gt 0 ]; then
    echo -e "1. ${RED}CRITIQUE${NC}: Corriger tous les problèmes critiques"
fi

if [ "${HIGH_ISSUES}" -gt 0 ]; then
    echo -e "2. ${YELLOW}ÉLEVÉ${NC}: Implémenter les contrôles de sécurité manquants"
fi

echo -e "3. ${BLUE}GÉNÉRAL${NC}: Effectuer un pentest avant mise en production"
echo -e "4. ${BLUE}GÉNÉRAL${NC}: Mettre en place un SOC pour le monitoring"
echo -e "5. ${BLUE}GÉNÉRAL${NC}: Formation sécurité pour l'équipe de développement"

echo ""
echo -e "${GREEN}✅ Analyse de sécurité terminée${NC}"
echo -e "Rapport généré le: $(date)"
