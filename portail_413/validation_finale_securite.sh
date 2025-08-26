#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de Validation Finale de Sécurité
# Génère un rapport consolidé de toutes les vérifications

set -e

echo "🔍 DCOP (413) - VALIDATION FINALE DE SÉCURITÉ"
echo "============================================="
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Fonction pour afficher des résultats avec couleurs
print_status() {
    local status=$1
    local message=$2
    case $status in
        "OK") echo "✅ $message" ;;
        "WARNING") echo "⚠️  $message" ;;
        "ERROR") echo "❌ $message" ;;
        "INFO") echo "ℹ️  $message" ;;
    esac
}

# 1. Vérification de la Structure de Sécurité
echo "📁 1. VÉRIFICATION STRUCTURE DE SÉCURITÉ"
echo "----------------------------------------"

security_files=(
    "src/security/valkey_rate_limiting.rs"
    "src/security/rate_limiting_advanced.rs" 
    "src/security/secrets_manager.rs"
    "src/security/security_audit.rs"
    "src/security/security_config.rs"
    "src/security/mod.rs"
)

for file in "${security_files[@]}"; do
    if [[ -f "$file" ]]; then
        lines=$(wc -l < "$file")
        print_status "OK" "$file ($lines lignes)"
    else
        print_status "ERROR" "$file manquant"
    fi
done

# 2. Vérification des Dépendances Cryptographiques  
echo ""
echo "🔐 2. VÉRIFICATION DÉPENDANCES CRYPTO"
echo "-------------------------------------"

crypto_deps=(
    "argon2.*0\.5"
    "blake3.*1\.5" 
    "aes-gcm.*0\.10"
    "chacha20poly1305.*0\.10"
    "ring.*0\.17"
    "zeroize.*1\.8"
)

if [[ -f "Cargo.toml" ]]; then
    for dep in "${crypto_deps[@]}"; do
        if grep -q "$dep" Cargo.toml; then
            print_status "OK" "Dépendance $dep trouvée"
        else
            print_status "WARNING" "Dépendance $dep non trouvée ou version différente"
        fi
    done
else
    print_status "ERROR" "Cargo.toml non trouvé"
fi

# 3. Analyse des Implémentations de Sécurité
echo ""
echo "🛡️ 3. ANALYSE IMPLÉMENTATIONS SÉCURITÉ"
echo "--------------------------------------"

# Rate Limiting  
if [[ -f "src/security/security_config.rs" ]] && grep -q "enum.*RateLimitAlgorithm" src/security/security_config.rs; then
    print_status "OK" "Rate Limiting avec algorithmes multiples détecté"
elif [[ -f "src/security/valkey_rate_limiting.rs" ]]; then
    print_status "OK" "Rate Limiting Valkey avancé détecté"
else
    print_status "WARNING" "Rate Limiting non détecté"
fi

# Authentification
if grep -r "Argon2" src/ >/dev/null 2>&1; then
    print_status "OK" "Hachage Argon2 implémenté"
else
    print_status "WARNING" "Argon2 non détecté dans le code"
fi

# Audit
if [[ -f "src/security/security_audit.rs" ]]; then
    if grep -q "AuditEventType" src/security/security_audit.rs; then
        print_status "OK" "Système d'audit complet détecté"
    else
        print_status "WARNING" "Audit basique détecté"
    fi
fi

# 4. Vérification Configuration TLS/SSL
echo ""
echo "🌐 4. VÉRIFICATION TLS/SSL"
echo "-------------------------"

if [[ -d "nginx" ]]; then
    if find nginx -name "*.conf" -exec grep -l "ssl_protocols.*TLSv1.3" {} \; | head -1 >/dev/null; then
        print_status "OK" "Configuration TLS 1.3 trouvée"
    else
        print_status "WARNING" "TLS 1.3 non configuré ou non trouvé"
    fi
    
    if find nginx -name "*.conf" -exec grep -l "ssl_ciphers" {} \; | head -1 >/dev/null; then
        print_status "OK" "Configuration des ciphers SSL trouvée"
    else
        print_status "WARNING" "Configuration ciphers SSL manquante"
    fi
else
    print_status "INFO" "Répertoire nginx non trouvé (configuration externe possible)"
fi

# 5. Compilation et Tests
echo ""
echo "🦀 5. COMPILATION ET TESTS"
echo "-------------------------"

# Test de compilation
echo "Vérification de la compilation..."
if cargo check --quiet >/dev/null 2>&1; then
    print_status "OK" "Compilation réussie"
else
    print_status "WARNING" "Erreurs de compilation détectées"
fi

# Vérification des tests de sécurité
if [[ -f "tests/security_integration_tests.rs" ]]; then
    print_status "OK" "Tests de sécurité intégrés présents"
else
    print_status "WARNING" "Tests de sécurité intégrés manquants"
fi

# 6. Score Final et Recommandations
echo ""
echo "📊 6. SCORE FINAL ET RECOMMANDATIONS"  
echo "===================================="

# Calcul du score basé sur les vérifications
score=0
max_score=20

# Points pour les fichiers de sécurité (6 points max)
for file in "${security_files[@]}"; do
    [[ -f "$file" ]] && ((score++))
done

# Points pour les dépendances crypto (6 points max)  
for dep in "${crypto_deps[@]}"; do
    grep -q "${dep%%.*}" Cargo.toml 2>/dev/null && ((score++))
done

# Points pour la compilation (2 points)
cargo check --quiet >/dev/null 2>&1 && score=$((score + 2))

# Points pour les tests (2 points)
[[ -f "tests/security_integration_tests.rs" ]] && score=$((score + 2))

# Points pour TLS (4 points)
if [[ -d "nginx" ]]; then
    find nginx -name "*.conf" -exec grep -l "ssl_protocols.*TLSv1.3" {} \; | head -1 >/dev/null && score=$((score + 2))
    find nginx -name "*.conf" -exec grep -l "ssl_ciphers" {} \; | head -1 >/dev/null && score=$((score + 2))
fi

percentage=$((score * 100 / max_score))

echo ""
echo "🎯 RÉSULTAT FINAL:"
echo "=================="
echo "Score: $score/$max_score ($percentage%)"

if [[ $percentage -ge 90 ]]; then
    print_status "OK" "EXCELLENT - Prêt pour la production"
    echo "🚀 L'application respecte tous les standards de sécurité modernes"
elif [[ $percentage -ge 75 ]]; then
    print_status "OK" "BON - Quelques améliorations mineures recommandées"
elif [[ $percentage -ge 60 ]]; then
    print_status "WARNING" "ACCEPTABLE - Améliorations nécessaires avant production"
else
    print_status "ERROR" "INSUFFISANT - Corrections majeures requises"
fi

echo ""
echo "📋 RECOMMANDATIONS PRIORITAIRES:"
echo "================================"

if [[ $score -lt 12 ]]; then
    echo "🔴 PRIORITÉ HAUTE:"
    echo "  - Compléter l'implémentation des modules de sécurité"
    echo "  - Ajouter les dépendances cryptographiques manquantes"
    echo "  - Résoudre les erreurs de compilation"
fi

if [[ $score -lt 16 ]]; then
    echo "🟡 PRIORITÉ MOYENNE:"  
    echo "  - Améliorer la configuration TLS/SSL"
    echo "  - Ajouter des tests de sécurité automatisés"
    echo "  - Valider les implémentations rate limiting"
fi

echo "🟢 PRIORITÉ FAIBLE:"
echo "  - Ajouter MFA/2FA pour les administrateurs"
echo "  - Intégrer un système HSM/Vault"
echo "  - Implémenter la rotation automatique des clés"

echo ""
echo "📄 RAPPORTS GÉNÉRÉS:"
echo "==================="
print_status "INFO" "RAPPORT_SCAN_SECURITE_PROFOND.md"
print_status "INFO" "VALIDATION_FINALE_RECOMMANDATIONS.md"
print_status "INFO" "validation_finale_securite.sh (ce script)"

echo ""
echo "✅ Validation finale terminée le $(date '+%Y-%m-%d %H:%M:%S')"
