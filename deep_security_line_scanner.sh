#!/bin/bash
set -euo pipefail
# Scanner de sécurité ligne par ligne - Analyse exhaustive
# Détection de vulnérabilités cachées dans tout le codebase

echo "🔍 SCANNER SÉCURITÉ LIGNE PAR LIGNE - ANALYSE EXHAUSTIVE"
echo "========================================================="
echo "Recherche de vulnérabilités cachées dans tous les fichiers"
echo ""

CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# Couleurs pour output
RED='\033[0;31m'
YELLOW='\033[1;33m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

log_critical() {
    echo -e "${RED}🔴 CRITIQUE: $1${NC}"
    ((CRITICAL_ISSUES++))
}

log_high() {
    echo -e "${YELLOW}🟡 ÉLEVÉ: $1${NC}"
    ((HIGH_ISSUES++))
}

log_medium() {
    echo -e "${ORANGE}⚠️  MOYEN: $1${NC}"
    ((MEDIUM_ISSUES++))
}

log_info() {
    echo -e "${BLUE}ℹ️  INFO: $1${NC}"
    ((LOW_ISSUES++))
}

echo "📂 1. ANALYSE DES FICHIERS DE CONFIGURATION"
echo "============================================"

# Scan docker-compose.yml
if [ -f "docker-compose.full.yml" ]; then
    echo "🔍 Analyse docker-compose.full.yml..."
    
    # Vérifier mots de passe en dur
    if grep -n "password.*:" docker-compose.full.yml | grep -v "POSTGRES_PASSWORD_FILE"; then
        log_critical "Mots de passe en dur détectés dans docker-compose.full.yml"
    fi
    
    # Vérifier ports exposés
    exposed_ports=$(grep -n "ports:" docker-compose.full.yml -A 5 | grep -o '[0-9]\+:[0-9]\+')
    for port in $exposed_ports; do
        external_port=$(echo $port | cut -d: -f1)
        if [ "$external_port" = "5432" ]; then
            log_high "Port PostgreSQL 5432 exposé publiquement - Risque d'accès direct"
        fi
        if [ "$external_port" = "8080" ]; then
            log_medium "Port backend 8080 exposé - Devrait passer par proxy uniquement"
        fi
    done
    
    # Vérifier conteneurs privilégiés
    if grep -n "privileged.*true" docker-compose.full.yml; then
        log_critical "Conteneurs privilégiés détectés - Risque d'escalation"
    fi
    
    # Vérifier network mode host
    if grep -n "network_mode.*host" docker-compose.full.yml; then
        log_high "Network mode host détecté - Isolation réseau compromise"
    fi
fi

echo ""
echo "🌐 2. ANALYSE CONFIGURATION NGINX"
echo "=================================="

if [ -f "portail_413/nginx/nginx.conf" ]; then
    echo "🔍 Analyse nginx.conf..."
    
    # Vérifier version Nginx exposée
    if ! grep -q "server_tokens off" portail_413/nginx/nginx.conf; then
        log_medium "Version Nginx exposée - Information disclosure"
    fi
    
    # Vérifier SSL/TLS configuration
    if ! grep -q "ssl_protocols.*TLSv1.3" portail_413/nginx/nginx.conf; then
        log_high "TLS 1.3 non configuré - Configuration SSL faible"
    fi
    
    # Vérifier ciphers sécurisés
    if grep -q "ssl_ciphers" portail_413/nginx/nginx.conf; then
        if grep "ssl_ciphers" portail_413/nginx/nginx.conf | grep -q "RC4\|MD5\|SHA1"; then
            log_critical "Ciphers faibles détectés (RC4/MD5/SHA1)"
        fi
    fi
    
    # Vérifier rate limiting
    rate_limit=$(grep -o "rate=[0-9]\+r/[sm]" portail_413/nginx/nginx.conf | head -1)
    if [ -n "$rate_limit" ]; then
        rate_value=$(echo $rate_limit | grep -o '[0-9]\+')
        if [ "$rate_value" -gt 100 ]; then
            log_medium "Rate limiting trop permissif: $rate_limit"
        fi
    fi
    
    # Vérifier logs d'accès
    if ! grep -q "access_log" portail_413/nginx/nginx.conf; then
        log_medium "Logs d'accès non configurés - Monitoring insuffisant"
    fi
fi

echo ""
echo "🦀 3. ANALYSE CODE RUST/ACTIX"
echo "=============================="

# Scan tous les fichiers .rs
find portail_413/src -name "*.rs" -type f | while read -r rust_file; do
    if [ -f "$rust_file" ]; then
        echo "🔍 Analyse $rust_file..."
        
        # Vérifier bcrypt encore utilisé
        if grep -n "bcrypt::" "$rust_file"; then
            log_high "bcrypt encore utilisé dans $rust_file - Migrer vers Argon2"
        fi
        
        # Vérifier secrets en dur
        if grep -n "secret.*=.*\"[a-zA-Z0-9]\{10,\}\"" "$rust_file"; then
            log_critical "Secret en dur détecté dans $rust_file"
        fi
        
        # Vérifier SQL raw
        if grep -n "execute.*format!\|query.*format!" "$rust_file"; then
            log_critical "Injection SQL possible dans $rust_file - format! avec query"
        fi
        
        # Vérifier unwrap() dangereux
        unwrap_count=$(grep -c "\.unwrap()" "$rust_file" 2>/dev/null || echo 0)
        if [ "$unwrap_count" -gt 5 ]; then
            log_medium "Trop d'unwrap() dans $rust_file ($unwrap_count) - Gestion d'erreur insuffisante"
        fi
        
        # Vérifier debug prints
        if grep -n "println!\|dbg!\|eprintln!" "$rust_file"; then
            log_medium "Debug prints détectés dans $rust_file - Fuite d'informations possible"
        fi
        
        # Vérifier unsafe code
        if grep -n "unsafe" "$rust_file"; then
            log_high "Code unsafe détecté dans $rust_file - Review sécurité requise"
        fi
        
        # Vérifier hardcoded IPs
        if grep -n "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" "$rust_file" | grep -v "127.0.0.1\|0.0.0.0"; then
            log_medium "IP hardcodée détectée dans $rust_file"
        fi
    fi
done

echo ""
echo "📦 4. ANALYSE CARGO.TOML ET DÉPENDANCES"
echo "========================================"

if [ -f "portail_413/Cargo.toml" ]; then
    echo "🔍 Analyse Cargo.toml..."
    
    # Vérifier dépendances avec vulnérabilités connues
    vulnerable_deps=("openssl 0.10.0" "actix-web 3.0" "serde 1.0.100" "tokio 1.0.0")
    
    for dep in "${vulnerable_deps[@]}"; do
        dep_name=$(echo "$dep" | cut -d' ' -f1)
        vuln_version=$(echo "$dep" | cut -d' ' -f2)
        if grep -q "^$dep_name.*=.*\"$vuln_version\"" portail_413/Cargo.toml; then
            log_high "Dépendance vulnérable: $dep"
        fi
    done
    
    # Vérifier si bcrypt encore présent
    if grep -q "bcrypt" portail_413/Cargo.toml; then
        log_high "bcrypt encore dans Cargo.toml - Supprimer après migration Argon2"
    fi
    
    # Vérifier features de sécurité manquantes
    if ! grep -q "rustls" portail_413/Cargo.toml; then
        log_medium "rustls manquant - TLS natif Rust recommandé"
    fi
fi

echo ""
echo "🗂️ 5. ANALYSE FICHIERS SECRETS ET CONFIG"
echo "=========================================="

# Scan répertoires de secrets
for secrets_dir in secrets secrets_secure portail_413/secrets portail_413/secrets_secure; do
    if [ -d "$secrets_dir" ]; then
        echo "🔍 Analyse répertoire $secrets_dir..."
        
        # Vérifier permissions
        for secret_file in "$secrets_dir"/*; do
            if [ -f "$secret_file" ]; then
                perms=$(stat -c "%a" "$secret_file" 2>/dev/null)
                if [ "$perms" != "600" ]; then
                    log_high "Permissions incorrectes sur $secret_file: $perms (devrait être 600)"
                fi
                
                # Vérifier taille des secrets
                size=$(stat -c "%s" "$secret_file" 2>/dev/null)
                if [ "$size" -lt 32 ]; then
                    log_medium "Secret trop court dans $secret_file: $size bytes (min 32)"
                fi
                
                # Vérifier si le secret est en base64/hex valide
                if file "$secret_file" | grep -q "ASCII text"; then
                    content=$(head -1 "$secret_file")
                    if [ ${#content} -lt 32 ]; then
                        log_medium "Secret faible dans $secret_file (longueur: ${#content})"
                    fi
                fi
            fi
        done
    fi
done

echo ""
echo "🌍 6. ANALYSE CONFIGURATION WEB"
echo "==============================="

# Vérifier fichiers de configuration web
web_configs=("portail_413/nginx/security_headers.conf" "portail_413/nginx/csp_advanced.conf")

for config in "${web_configs[@]}"; do
    if [ -f "$config" ]; then
        echo "🔍 Analyse $config..."
        
        # Vérifier CSP
        if echo "$config" | grep -q "csp"; then
            if ! grep -q "default-src 'self'" "$config"; then
                log_high "CSP default-src manquant dans $config"
            fi
            if grep -q "'unsafe-eval'" "$config"; then
                log_medium "CSP unsafe-eval détecté dans $config"
            fi
            if grep -q "'unsafe-inline'" "$config"; then
                log_medium "CSP unsafe-inline détecté dans $config"
            fi
        fi
        
        # Vérifier HSTS
        if ! grep -q "Strict-Transport-Security" "$config"; then
            log_high "HSTS manquant dans $config"
        fi
        
        # Vérifier X-Frame-Options
        if ! grep -q "X-Frame-Options" "$config"; then
            log_medium "X-Frame-Options manquant dans $config"
        fi
    fi
done

echo ""
echo "📊 7. ANALYSE LOGS ET MONITORING"
echo "================================"

# Vérifier configuration de logging
log_files=("app.log" "portail_413/app.log" "/var/log/nginx/access.log" "/var/log/nginx/error.log")

for log_file in "${log_files[@]}"; do
    if [ -f "$log_file" ]; then
        echo "🔍 Analyse $log_file..."
        
        # Vérifier si des secrets sont loggés
        if grep -i "password\|secret\|token\|key" "$log_file" | head -5; then
            log_critical "Secrets potentiels loggés dans $log_file"
        fi
        
        # Vérifier erreurs SQL
        if grep -i "sql.*error\|database.*error" "$log_file" | head -3; then
            log_medium "Erreurs SQL exposées dans $log_file"
        fi
        
        # Vérifier stack traces
        if grep -c "stack trace\|backtrace" "$log_file" > /dev/null; then
            log_medium "Stack traces exposées dans $log_file"
        fi
    fi
done

echo ""
echo "🔐 8. ANALYSE SCRIPTS DE DÉPLOIEMENT"
echo "===================================="

# Scan tous les scripts shell
find . -name "*.sh" -type f | while read -r script; do
    if [ -f "$script" ]; then
        echo "🔍 Analyse $script..."
        
        # Vérifier mots de passe en dur
        if grep -n "password.*=.*['\"][a-zA-Z0-9]" "$script"; then
            log_critical "Mot de passe en dur dans $script"
        fi
        
        # Vérifier commandes dangereuses
        for cmd in "${dangerous_cmds[@]}"; do
            if grep -q "$cmd" "$script"; then
                log_high "Commande dangereuse dans $script: $cmd"
            fi
        done
        
        # Vérifier variables non quotées
        if grep -n '\$[A-Z_]\+[^"'\''$]' "$script" | head -3; then
            log_medium "Variables non quotées dans $script - Risque d'injection"
        fi
        
        # Vérifier set -e manquant
        if ! grep -q "set -e" "$script" && [ "$(basename $script)" != "validate_production_security.sh" ]; then
            log_info "set -e manquant dans $script - Gestion d'erreur recommandée"
        fi
    fi
done

echo ""
echo "🐳 9. ANALYSE CONFIGURATION DOCKER"
echo "=================================="

# Scan Dockerfiles
find . -name "Dockerfile*" -type f | while read -r dockerfile; do
    if [ -f "$dockerfile" ]; then
        echo "🔍 Analyse $dockerfile..."
        
        # Vérifier user root
        if ! grep -q "USER.*[^root]" "$dockerfile"; then
            log_high "Conteneur s'exécute en root dans $dockerfile"
        fi
        
        # Vérifier secrets dans layers
        if grep -n "ENV.*PASSWORD\|ENV.*SECRET\|ENV.*KEY" "$dockerfile"; then
            log_critical "Secrets dans ENV variables de $dockerfile"
        fi
        
        # Vérifier ADD vs COPY
        if grep -n "ADD.*http" "$dockerfile"; then
            log_medium "ADD avec URL dans $dockerfile - Préférer COPY"
        fi
        
        # Vérifier packages inutiles
        bloat_packages=("vim" "nano" "wget" "curl" "ssh")
        for pkg in "${bloat_packages[@]}"; do
            if grep -q "apt.*install.*$pkg\|apk.*add.*$pkg" "$dockerfile"; then
                log_info "Package non essentiel dans $dockerfile: $pkg"
            fi
        done
    fi
done

echo ""
echo "📄 10. ANALYSE FICHIERS DE DOCUMENTATION"
echo "========================================"

# Vérifier si des secrets sont dans la documentation
find . -name "*.md" -type f | while read -r md_file; do
    if [ -f "$md_file" ]; then
        # Vérifier secrets exposés
        if grep -i "password.*[:=].*[a-zA-Z0-9]\{8,\}\|secret.*[:=].*[a-zA-Z0-9]\{8,\}" "$md_file"; then
            log_critical "Secret potentiel exposé dans $md_file"
        fi
        
        # Vérifier IPs privées exposées
        if grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" "$md_file" | grep -E "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
            log_medium "Adresses IP privées exposées dans $md_file"
        fi
    fi
done

echo ""
echo "📋 RÉSUMÉ FINAL DU SCAN LIGNE PAR LIGNE"
echo "========================================"

TOTAL_ISSUES=$((CRITICAL_ISSUES + HIGH_ISSUES + MEDIUM_ISSUES + LOW_ISSUES))

echo "🔴 Vulnérabilités CRITIQUES : "${CRITICAL_ISSUES}""
echo "🟡 Vulnérabilités ÉLEVÉES   : "${HIGH_ISSUES}""  
echo "⚠️  Vulnérabilités MOYENNES  : "${MEDIUM_ISSUES}""
echo "ℹ️  Problèmes MINEURS        : "${LOW_ISSUES}""
echo "📊 TOTAL                    : "${TOTAL_ISSUES}""

echo ""
if [ "${CRITICAL_ISSUES}" -eq 0 ] && [ "${HIGH_ISSUES}" -eq 0 ]; then
    echo "🏆 EXCELLENT : Aucune vulnérabilité critique ou élevée détectée"
    if [ "${MEDIUM_ISSUES}" -eq 0 ]; then
        echo "✨ PARFAIT : Score de sécurité optimal maintenu"
        exit 0
    else
        echo "✅ BON : Quelques améliorations mineures possibles"
        exit 0
    fi
elif [ "${CRITICAL_ISSUES}" -eq 0 ] && [ "${HIGH_ISSUES}" -le 2 ]; then
    echo "✅ ACCEPTABLE : Vulnérabilités élevées limitées"
    exit 0
elif [ "${CRITICAL_ISSUES}" -eq 0 ]; then
    echo "⚠️  MOYEN : Corrections recommandées"
    exit 1
else
    echo "🚨 CRITIQUE : Action immédiate requise"
    exit 2
fi
