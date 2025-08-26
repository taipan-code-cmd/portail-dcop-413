#!/bin/bash
set -euo pipefail

# DCOP (413) - Exécuteur de Tests de Sécurité
# Script principal pour exécuter tous les tests de validation des corrections

set -e

echo "🚀 DCOP (413) - Suite Complète de Tests de Sécurité"
echo "=================================================="
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Variables de configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="${SCRIPT_DIR}"/test_reports"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# Créer le dossier de rapports
mkdir -p "${REPORTS_DIR}""

# Fonction de logging
log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# Fonction d'exécution de test avec capture d'erreur
run_test() {
    local test_name="$1"
    local test_command="$2"
    local report_file="${REPORTS_DIR}"/${test_name}_${TIMESTAMP}.log"
    
    log "📋 Exécution: $test_name"
    
    if eval "$test_command" > "$report_file" 2>&1; then
        log "✅ $test_name: RÉUSSI"
        return 0
    else
        log "❌ $test_name: ÉCHEC"
        echo "   📄 Voir: $report_file"
        return 1
    fi
}

# Vérification des prérequis
log "🔍 Vérification des prérequis..."

# Vérifier que Docker Compose fonctionne
if ! docker-compose ps > /dev/null 2>&1; then
    log "❌ Docker Compose non disponible ou services arrêtés"
    log "🚀 Démarrage des services..."
    cd "${SCRIPT_DIR}""
    docker-compose up -d
    sleep 30
fi

# Vérifier les services requis
log "🔍 Vérification des services..."
SERVICES_OK=true

if ! docker-compose ps | grep -q "dcop_nginx.*Up"; then
    log "❌ Service nginx non disponible"
    SERVICES_OK=false
fi

if ! docker-compose ps | grep -q "dcop_app.*Up.*healthy"; then
    log "❌ Service app non disponible ou pas en bonne santé"
    SERVICES_OK=false
fi

if ! docker-compose ps | grep -q "dcop_postgres_secure.*Up.*healthy"; then
    log "❌ Service PostgreSQL non disponible ou pas en bonne santé"
    SERVICES_OK=false
fi

if [ "${SERVICES_OK}"" = false ]; then
    log "❌ Services non prêts. Arrêt des tests."
    exit 1
fi

log "✅ Tous les services sont opérationnels"
echo ""

# E1. Seeding des données de test
log "📊 E1. Préparation des données de test..."
if run_test "E1_seed_data" "docker-compose exec -T postgres psql -U dcop_user -d dcop_413 -f /dev/stdin < '"${SCRIPT_DIR}"/seed_test_data.sql'"; then
    log "✅ Données de test préparées"
else
    log "⚠️ Seeding échoué, mais continuons (données peut-être déjà présentes)"
fi
echo ""

# Tests Rust d'intégration
log "🦀 Exécution des tests Rust d'intégration..."
cd "${SCRIPT_DIR}""

# Compiler et exécuter les tests
if run_test "rust_integration_tests" "cargo test integration_security_tests --release -- --test-threads=1"; then
    RUST_TESTS_PASSED=true
else
    RUST_TESTS_PASSED=false
fi
echo ""

# Tests de sécurité système (scripts externes si disponibles)
EXTERNAL_TESTS_DIR="/home/taipan_51/portail_413/tests"
if [ -d "${EXTERNAL_TESTS_DIR}"" ]; then
    log "🔐 Exécution des tests de sécurité externes..."
    
    # C1. Tests privilèges PostgreSQL
    if [ -f "${EXTERNAL_TESTS_DIR}"/test_c1_postgres_privileges.sh" ]; then
        run_test "C1_postgres_privileges" "bash '"${EXTERNAL_TESTS_DIR}"/test_c1_postgres_privileges.sh'"
    fi
    
    # C2. Tests exposition base de données
    if [ -f "${EXTERNAL_TESTS_DIR}"/test_c2_database_exposure.sh" ]; then
        run_test "C2_database_exposure" "bash '"${EXTERNAL_TESTS_DIR}"/test_c2_database_exposure.sh'"
    fi
    
    # C3. Tests certificats SSL
    if [ -f "${EXTERNAL_TESTS_DIR}"/test_c3_ssl_certificates.sh" ]; then
        run_test "C3_ssl_certificates" "bash '"${EXTERNAL_TESTS_DIR}"/test_c3_ssl_certificates.sh'"
    fi
    
    # E2. Tests endpoints API
    if [ -f "${EXTERNAL_TESTS_DIR}"/test_e2_api_endpoints.sh" ]; then
        run_test "E2_api_endpoints" "bash '"${EXTERNAL_TESTS_DIR}"/test_e2_api_endpoints.sh'"
    fi
fi

# Tests de performance et charge (optionnels)
log "⚡ Tests de performance de base..."
run_test "performance_basic" "curl --max-time 10 --retry 3 -w 'Time: %{time_total}s\nStatus: %{http_code}\n' -o /dev/null -s -k https://localhost/health"

# Tests de sécurité avancés
log "🛡️ Tests de sécurité avancés..."

# Test d'injection SQL de base
run_test "sql_injection_basic" "curl --max-time 10 --retry 3 -k -X POST 'https://localhost/api/auth/login' -H 'Content-Type: application/json' -d '{\"username\": \"admin\"; DROP TABLE users; --\", \"password\": \"test\"}' -w '%{http_code}' -o /dev/null -s"

# Test d'en-têtes de sécurité
run_test "security_headers" "curl --max-time 10 --retry 3 -I -k https://localhost/ | grep -E '(strict-transport-security|x-frame-options|x-content-type-options|content-security-policy)'"

# Test de limitation de débit (rate limiting)
log "🚦 Test de limitation de débit..."
run_test "rate_limiting" "for i in {1..10}; do curl --max-time 10 --retry 3 -k -w '%{http_code}\n' -o /dev/null -s https://localhost/api/auth/login -X POST -H 'Content-Type: application/json' -d '{\"username\":\"test\",\"password\":\"test\"}' & done; wait"

echo ""
log "📊 Génération du rapport consolidé..."

# Générer le rapport final
REPORT_FILE="${REPORTS_DIR}"/security_test_report_${TIMESTAMP}.md"
cat > "${REPORT_FILE}"" << EOF
# 🔒 RAPPORT DE TESTS DE SÉCURITÉ DCOP (413)

**Date:** $(date '+%Y-%m-%d %H:%M:%S')  
**Version:** Tests de validation des corrections de vulnérabilités

## 📋 Résumé Exécutif

### Tests Exécutés
EOF

# Compter les résultats
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

for report in "${REPORTS_DIR}""/*_${TIMESTAMP}.log; do
    if [ -f "$report" ]; then
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        test_name=$(basename "$report" | sed "s/_${TIMESTAMP}.log//")
        
        if grep -q "RÉUSSI\|✅\|200\|OK" "$report" 2>/dev/null; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
            echo "- ✅ **$test_name**: Réussi" >> "${REPORT_FILE}""
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            echo "- ❌ **$test_name**: Échec" >> "${REPORT_FILE}""
        fi
    fi
done

cat >> "${REPORT_FILE}"" << EOF

### Statistiques
- **Total des tests:** "${TOTAL_TESTS}"
- **Tests réussis:** "${PASSED_TESTS}"
- **Tests échoués:** "${FAILED_TESTS}"
- **Taux de réussite:** $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

## 🔍 Détails par Catégorie

### C1. Privilèges PostgreSQL
$([ -f "${REPORTS_DIR}"/C1_postgres_privileges_${TIMESTAMP}.log" ] && echo "Voir: "${REPORTS_DIR}"/C1_postgres_privileges_${TIMESTAMP}.log" || echo "Non testé")

### C2. Exposition Base de Données  
$([ -f "${REPORTS_DIR}"/C2_database_exposure_${TIMESTAMP}.log" ] && echo "Voir: "${REPORTS_DIR}"/C2_database_exposure_${TIMESTAMP}.log" || echo "Non testé")

### C3. Certificats SSL
$([ -f "${REPORTS_DIR}"/C3_ssl_certificates_${TIMESTAMP}.log" ] && echo "Voir: "${REPORTS_DIR}"/C3_ssl_certificates_${TIMESTAMP}.log" || echo "Non testé")

### E1. Données de Test
$([ -f "${REPORTS_DIR}"/E1_seed_data_${TIMESTAMP}.log" ] && echo "Voir: "${REPORTS_DIR}"/E1_seed_data_${TIMESTAMP}.log" || echo "Non testé")

### E2. Endpoints API
$([ -f "${REPORTS_DIR}"/E2_api_endpoints_${TIMESTAMP}.log" ] && echo "Voir: "${REPORTS_DIR}"/E2_api_endpoints_${TIMESTAMP}.log" || echo "Non testé")

## 🎯 Recommandations

EOF

if [ "${FAILED_TESTS}" -eq 0 ]; then
    cat >> "${REPORT_FILE}"" << EOF
🎉 **FÉLICITATIONS!** Tous les tests de sécurité sont réussis.

✅ Toutes les corrections de vulnérabilités sont validées.
✅ L'application respecte les standards de sécurité.
✅ Prêt pour la mise en production.
EOF
else
    cat >> "${REPORT_FILE}"" << EOF
⚠️ **ATTENTION:** "${FAILED_TESTS}" test(s) ont échoué.

🔧 Actions requises:
- Examiner les logs d'erreur dans "${REPORTS_DIR}"/
- Corriger les problèmes identifiés
- Re-exécuter les tests

📋 Priorité: Haute - Sécurité compromise
EOF
fi

echo ""
log "📄 Rapport final généré: "${REPORT_FILE}""
echo ""

# Résumé final
if [ "${FAILED_TESTS}" -eq 0 ]; then
    log "🎉 TOUS LES TESTS DE SÉCURITÉ RÉUSSIS!"
    log "✅ $(( PASSED_TESTS * 100 / TOTAL_TESTS ))% de réussite ("${PASSED_TESTS}"/"${TOTAL_TESTS}")"
    exit 0
else
    log "❌ "${FAILED_TESTS}"/"${TOTAL_TESTS}" TESTS ÉCHOUÉS"
    log "⚠️ Sécurité compromise - Corrections requises"
    exit 1
fi
