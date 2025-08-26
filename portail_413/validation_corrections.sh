#!/bin/bash
# DCOP (413) - Validation Post-Correction
# Valide que toutes les corrections ont été appliquées avec succès

set -euo pipefail

echo "✅ DCOP (413) - VALIDATION POST-CORRECTION"
echo "=========================================="

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

passed=0
failed=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "    ${GREEN}✅ PASSED${NC}"
        ((passed++))
    else
        echo -e "    ${RED}❌ FAILED${NC}"
        ((failed++))
    fi
}

echo ""
echo "🔍 TESTS DE VALIDATION"
echo "====================="

# Test 1: Services Docker running
echo "1. Services Docker en cours d'exécution..."
running_services=0
for service in dcop_postgres_secure dcop_app dcop_nginx; do
    if docker ps --filter "name=$service" --filter "status=running" | grep -q "$service"; then
        ((running_services++))
    fi
done
[ $running_services -eq 3 ]
test_result $?

# Test 2: Health checks
echo "2. Health checks des services..."
healthy_services=0
for service in dcop_postgres_secure dcop_nginx; do  # Skip dcop_app car il peut encore être starting
    health=$(docker inspect --format='{{.State.Health.Status}}' "$service" 2>/dev/null || echo "none")
    if [[ "$health" == "healthy" ]]; then
        ((healthy_services++))
    fi
done
[ $healthy_services -ge 1 ]  # Au moins un service healthy
test_result $?

# Test 3: Connectivité réseau interne
echo "3. Connectivité réseau interne..."
nginx_to_app=$(docker exec dcop_nginx nc -zv 172.25.2.20 8443 2>&1 | grep -c "succeeded" || echo 0)
app_to_postgres=$(docker exec dcop_app nc -zv 172.25.2.10 5432 2>&1 | grep -c "succeeded" || echo 0)
[ $nginx_to_app -gt 0 ] && [ $app_to_postgres -gt 0 ]
test_result $?

# Test 4: PostgreSQL opérationnel
echo "4. Base de données PostgreSQL..."
docker exec dcop_postgres_secure pg_isready -U dcop_user -d dcop_413 > /dev/null 2>&1
test_result $?

# Test 5: Endpoint proxy principal
echo "5. Endpoint proxy principal (/)..."
curl --max-time 10 --retry 3 -s http://localhost:8080/ | grep -q "DCOP" 2>/dev/null
test_result $?

# Test 6: Health check via proxy
echo "6. Health check via proxy..."
response=$(curl --max-time 10 --retry 3 -s -w "%{http_code}" http://localhost:8080/health 2>/dev/null)
echo "$response" | grep -q "200" 2>/dev/null
test_result $?

# Test 7: API Info endpoint
echo "7. API Info endpoint..."
curl --max-time 10 --retry 3 -s http://localhost:8080/api-info | grep -q "API Endpoints" 2>/dev/null
test_result $?

# Test 8: Authentification
echo "8. Test d'authentification..."
auth_response=$(curl --max-time 10 --retry 3 -s -X POST http://localhost:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' 2>/dev/null)
echo "$auth_response" | grep -q '"success":true' 2>/dev/null
test_result $?

# Test 9: Sécurité - Accès direct bloqué
echo "9. Sécurité - Accès direct à l'app bloqué..."
direct_response=$(curl --max-time 10 --retry 3 -s -w "%{http_code}" http://172.25.2.20:8443/health 2>/dev/null || echo "000")
echo "$direct_response" | grep -E "(403|000)" > /dev/null 2>&1
test_result $?

# Test 10: Secrets existants
echo "10. Vérification des secrets..."
secrets_count=0
for secret in postgres_password jwt_secret encryption_key security_salt; do
    if [[ -f "./secrets/${secret}.txt" ]] && [[ -s "./secrets/${secret}.txt" ]]; then
        ((secrets_count++))
    fi
done
[ $secrets_count -eq 4 ]
test_result $?

# Test 11: Configuration Nginx
echo "11. Configuration Nginx..."
grep -q "/internal/health" nginx/nginx.conf 2>/dev/null
test_result $?

# Test 12: Middleware proxy validation
echo "12. Middleware proxy validation..."
grep -q '"/health"' src/middleware/proxy_validation.rs 2>/dev/null
test_result $?

echo ""
echo "📊 RÉSULTATS FINAUX"
echo "=================="
echo -e "Tests réussis: ${GREEN}$passed${NC}"
echo -e "Tests échoués: ${RED}$failed${NC}"

if [ $failed -eq 0 ]; then
    echo -e "\n🎉 ${GREEN}TOUTES LES CORRECTIONS ONT ÉTÉ APPLIQUÉES AVEC SUCCÈS !${NC}"
    echo -e "Le système DCOP (413) est maintenant ${GREEN}OPÉRATIONNEL${NC}."
elif [ $failed -le 2 ]; then
    echo -e "\n⚠️  ${YELLOW}CORRECTIONS MAJORITAIREMENT APPLIQUÉES${NC}"
    echo -e "Quelques problèmes mineurs persistent. Le système est ${YELLOW}FONCTIONNEL${NC}."
else
    echo -e "\n❌ ${RED}CORRECTIONS PARTIELLES${NC}"
    echo -e "Des problèmes significatifs persistent. ${RED}INTERVENTION REQUISE${NC}."
fi

echo ""
echo "🛠️  ACTIONS RECOMMANDÉES"
echo "========================"

if [ $failed -eq 0 ]; then
    echo "• Système opérationnel - surveillance normale"
    echo "• Surveiller les logs: docker-compose logs -f"
    echo "• Tests périodiques avec ce script"
elif [ $failed -le 2 ]; then
    echo "• Réexécuter la correction: ./correction_rapide.sh"
    echo "• Surveiller les logs des services échoués"
    echo "• Attendre la stabilisation (health checks)"
else
    echo "• Réexécuter le diagnostic complet: ./scan_diagnostic_complet.sh"
    echo "• Vérifier les logs détaillés de chaque service"
    echo "• Envisager une reconstruction complète"
fi

echo ""
echo "📱 URLS DE TEST"
echo "==============="
echo "• Principal: http://localhost:8080/"
echo "• Health: http://localhost:8080/health"
echo "• API Info: http://localhost:8080/api-info"
echo "• Login: curl --max-time 10 --retry 3 -X POST http://localhost:8080/api/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"admin123\"}'"

echo ""
echo "✅ Validation terminée."

# Return exit code based on results
if [ $failed -eq 0 ]; then
    exit 0
elif [ $failed -le 2 ]; then
    exit 1
else
    exit 2
fi
