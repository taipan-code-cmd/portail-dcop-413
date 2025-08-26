#!/bin/bash
# Test complet des endpoints avec diagnostics détaillés

set -e

# Token JWT valide obtenu après authentification
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDEiLCJ1c2VybmFtZSI6ImFkbWluX3Rlc3QiLCJyb2xlIjoiQWRtaW4iLCJleHAiOjE3NTUxMDU5NTAsImlhdCI6MTc1NTEwNTA1MCwianRpIjoiZDUxNzlhYmMtYjZiNC00OWM5LTg2YTktN2I3MjM3M2M2MjhkIiwic2Vzc2lvbl9pZCI6IjU0OWQzYWZjLTlmYzctNDhjYi1hNDYxLTY4MzhjNTBjMWVjZSJ9.VDjcvka26T7jIj1wZLm8OTKPhNv154ZlOJ9J7-iJ_ds"

BASE_URL="https://localhost:443"

echo "=== DIAGNOSTIC APPROFONDI DES ENDPOINTS ==="
echo 

# Test 1: Validation du token (DOIT FONCTIONNER)
echo "### Test 1: Validation du token ###"
curl --max-time 10 --retry 3 -X GET "${BASE_URL}"/api/auth/validate" \
    -H "Authorization: Bearer "${TOKEN}"" \
    -s -k --max-time 10 | jq '.' || echo "ERREUR: Token invalide"
echo

# Test 2: Endpoint public (DOIT FONCTIONNER)  
echo "### Test 2: Endpoint public des statistiques ###"
curl --max-time 10 --retry 3 -X GET "${BASE_URL}"/api/public/statistics/dashboard" \
    -s -k --max-time 10 | jq '.' || echo "ERREUR: Endpoint public inaccessible"
echo

# Test 3: Endpoint protégé simple (DIAGNOSTIC CRITIQUE)
echo "### Test 3: Diagnostic endpoint visitors ###"
echo "Headers complets:"
curl --max-time 10 --retry 3 -X GET "${BASE_URL}"/api/visitors/" \
    -H "Authorization: Bearer "${TOKEN}"" \
    -H "Content-Type: application/json" \
    -v -s -k --max-time 10 2>&1 | head -n 30
echo

# Test 4: Endpoint alternatif avec informations détaillées
echo "### Test 4: Test endpoint admin (alternatif) ###"
curl --max-time 10 --retry 3 -X GET "${BASE_URL}"/api/admin/stats" \
    -H "Authorization: Bearer "${TOKEN}"" \
    -H "Content-Type: application/json" \
    -s -k --max-time 10 | jq '.' || echo "ERREUR: Endpoint admin inaccessible"
echo

# Test 5: Vérification des routes publiques vs privées
echo "### Test 5: Comparaison routes publiques vs privées ###"
echo "Public statistics (sans auth):"
curl --max-time 10 --retry 3 -X GET "${BASE_URL}"/api/public/statistics/visitors" \
    -s -k --max-time 5 | jq '.' || echo "Pas d'endpoint public visitors"

echo "Private statistics (avec auth):"
curl --max-time 10 --retry 3 -X GET "${BASE_URL}"/api/statistics/visitors" \
    -H "Authorization: Bearer "${TOKEN}"" \
    -s -k --max-time 5 | jq '.' || echo "Endpoint privé inaccessible"
echo

echo "=== FIN DU DIAGNOSTIC ==="
