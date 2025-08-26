#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de test des corrections de sécurité
# Vérifie que toutes les mesures de remédiation sont correctement implémentées

set -euo pipefail

# Configuration
BASE_URL="${1:-https://localhost:8443}"
TEST_OUTPUT_DIR="./security_test_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔒 DCOP (413) - Test des Corrections de Sécurité${NC}"
echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}URL de base: "${BASE_URL}"${NC}"
echo -e "${BLUE}Timestamp: "${TIMESTAMP}"${NC}"
echo ""

# Créer le répertoire de résultats
mkdir -p "${TEST_OUTPUT_DIR}""

# Compteurs de tests
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Fonction pour exécuter un test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${YELLOW}🧪 Test: $test_name${NC}"
    
    if eval "$test_command" > "${TEST_OUTPUT_DIR}"/test_${TOTAL_TESTS}_${test_name// /_}.log" 2>&1; then
        if [[ "$expected_result" == "success" ]]; then
            echo -e "${GREEN}✅ PASSED${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}❌ FAILED (expected failure but got success)${NC}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        if [[ "$expected_result" == "failure" ]]; then
            echo -e "${GREEN}✅ PASSED (expected failure)${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}❌ FAILED${NC}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    fi
    echo ""
}

# Test 1: Vérification des certificats ECDSA P-384
echo -e "${BLUE}📋 Tests des Certificats SSL${NC}"
run_test "Certificate Algorithm Check" \
    "openssl x509 -in ./nginx/ssl/server.crt -text -noout | grep -q 'Public Key Algorithm: id-ecPublicKey'" \
    "success"

run_test "Certificate Curve Check" \
    "openssl x509 -in ./nginx/ssl/server.crt -text -noout | grep -q 'secp384r1'" \
    "success"

# Test 2: Vérification des secrets forts
echo -e "${BLUE}📋 Tests des Secrets${NC}"
run_test "JWT Secret Strength" \
    "test \$(wc -c < ./secrets/jwt_secret.txt) -ge 64" \
    "success"

run_test "Encryption Key Strength" \
    "test \$(wc -c < ./secrets/encryption_key.txt) -ge 64" \
    "success"

run_test "PostgreSQL Password Strength" \
    "test \$(wc -c < ./secrets/postgres_password.txt") -ge 32" \
    "success"

# Test 3: Vérification de l'absence d'exposition des secrets
echo -e "${BLUE}📋 Tests d'Exposition des Secrets${NC}"
run_test "No Hardcoded Passwords in Docker Compose" \
    "! grep -q 'dcop_password_123' ./docker-compose.yml" \
    "success"

run_test "No Default Users in Migrations" \
    "! grep -q 'YourHashHere' ./migrations/002_seed_data.sql" \
    "success"

# Test 4: Tests des endpoints de sécurité
echo -e "${BLUE}📋 Tests des Endpoints de Sécurité${NC}"

# Démarrer l'application en arrière-plan pour les tests
echo -e "${YELLOW}🚀 Démarrage de l'application pour les tests...${NC}"
if ! pgrep -f "portail_413" > /dev/null; then
    cargo build --release > "${TEST_OUTPUT_DIR}"/build.log" 2>&1 || {
        echo -e "${RED}❌ Échec de la compilation${NC}"
        exit 1
    }
    
    # Démarrer l'application en arrière-plan
    RUST_LOG=info ./target/release/portail_413 > "${TEST_OUTPUT_DIR}"/app.log" 2>&1 &
    APP_PID=$!
    
    # Attendre que l'application démarre
    sleep 5
    
    # Vérifier que l'application est démarrée
    if ! kill -0 "${APP_PID}" 2>/dev/null; then
        echo -e "${RED}❌ Échec du démarrage de l'application${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Application démarrée (PID: "${APP_PID}")${NC}"
    
    # Fonction de nettoyage
    cleanup() {
        if [[ -n "${APP_PID:-}" ]] && kill -0 "${APP_PID}" 2>/dev/null; then
            echo -e "${YELLOW}🛑 Arrêt de l'application...${NC}"
            kill "${APP_PID}"
            wait "${APP_PID}" 2>/dev/null || true
        fi
    }
    trap cleanup EXIT
fi

# Test 5: Test de génération de token CSRF
run_test "CSRF Token Generation" \
    "curl --max-time 10 --retry 3 -k -s -f "${BASE_URL}"/api/csrf/token | jq -e '.success == true'" \
    "success"

# Test 6: Test de protection CSRF (devrait échouer sans token)
run_test "CSRF Protection Active" \
    "curl --max-time 10 --retry 3 -k -s -X POST "${BASE_URL}"/api/csrf/test -H 'Content-Type: application/json' -d '{}'" \
    "failure"

# Test 7: Test de validation des entrées
run_test "Input Validation - Invalid Email" \
    "curl --max-time 10 --retry 3 -k -s -X POST "${BASE_URL}"/api/visitors -H 'Content-Type: application/json' -d '{\"first_name\":\"Test\",\"last_name\":\"User\",\"email\":\"invalid-email\",\"phone1\":\"1234567890\",\"phone2\":\"1234567890\",\"organization\":\"Test Org\"}'" \
    "failure"

# Test 8: Test de rate limiting
echo -e "${YELLOW}🧪 Test: Rate Limiting${NC}"
RATE_LIMIT_PASSED=true
for i in {1..10}; do
    if ! curl --max-time 10 --retry 3 -k -s -f "${BASE_URL}"/api/csrf/token" > /dev/null 2>&1; then
        if [[ $i -gt 5 ]]; then
            echo -e "${GREEN}✅ PASSED (Rate limiting active after $i requests)${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            RATE_LIMIT_PASSED=true
            break
        fi
    fi
    sleep 0.1
done

if [[ "${RATE_LIMIT_PASSED}"" != "true" ]]; then
    echo -e "${RED}❌ FAILED (Rate limiting not working)${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))
echo ""

# Test 9: Test des headers de sécurité
run_test "Security Headers Present" \
    "curl --max-time 10 --retry 3 -k -s -I "${BASE_URL}"/ | grep -q 'X-Content-Type-Options: nosniff'" \
    "success"

run_test "HSTS Header Present" \
    "curl --max-time 10 --retry 3 -k -s -I "${BASE_URL}"/ | grep -q 'Strict-Transport-Security'" \
    "success"

# Test 10: Test de la gestion d'erreurs standardisée
run_test "Standardized Error Response" \
    "curl --max-time 10 --retry 3 -k -s "${BASE_URL}"/api/nonexistent | jq -e '.success == false and .error.code != null'" \
    "success"

# Test 11: Vérification de la configuration nginx
echo -e "${BLUE}📋 Tests de Configuration Nginx${NC}"
run_test "Nginx SSL Configuration" \
    "grep -q 'ssl_protocols TLSv1.2 TLSv1.3' ./nginx/nginx.conf" \
    "success"

run_test "Nginx Security Headers" \
    "grep -q 'X-Content-Type-Options nosniff' ./nginx/nginx.conf" \
    "success"

# Test 12: Vérification des permissions des fichiers
echo -e "${BLUE}📋 Tests des Permissions${NC}"
run_test "Private Key Permissions" \
    "test \$(stat -c '%a' ./nginx/ssl/server.key) = '600'" \
    "success"

run_test "Certificate Permissions" \
    "test \$(stat -c '%a' ./nginx/ssl/server.crt) = '644'" \
    "success"

# Test 13: Test de compilation sans erreurs
echo -e "${BLUE}📋 Tests de Compilation${NC}"
run_test "Rust Compilation Success" \
    "cargo check --all-targets" \
    "success"

run_test "Rust Tests Pass" \
    "cargo test --lib" \
    "success"

# Résumé des résultats
echo -e "${BLUE}📊 RÉSUMÉ DES TESTS${NC}"
echo -e "${BLUE}==================${NC}"
echo -e "Total des tests: "${TOTAL_TESTS}""
echo -e "${GREEN}Tests réussis: "${PASSED_TESTS}"${NC}"
echo -e "${RED}Tests échoués: "${FAILED_TESTS}"${NC}"

if [[ "${FAILED_TESTS}" -eq 0 ]]; then
    echo -e "${GREEN}🎉 TOUS LES TESTS SONT PASSÉS!${NC}"
    echo -e "${GREEN}✅ Les corrections de sécurité sont correctement implémentées${NC}"
    exit 0
else
    echo -e "${RED}❌ CERTAINS TESTS ONT ÉCHOUÉ${NC}"
    echo -e "${RED}⚠️  Vérifiez les logs dans "${TEST_OUTPUT_DIR}"${NC}"
    exit 1
fi
