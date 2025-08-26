#!/bin/bash
# DCOP (413) - Script de Rotation Automatique des Secrets
# Conforme aux standards de sécurité gouvernementaux

set -euo pipefail

# Configuration
SECRETS_DIR="/app/secrets"
BACKUP_DIR="/app/secrets/backup"
LOG_FILE="/var/log/dcop/secret-rotation.log"
NOTIFICATION_URL="${DCOP_ALERT_WEBHOOK:-}"

# Fonctions utilitaires
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}""
}

error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "${LOG_FILE}"" >&2
}

send_alert() {
    local message="$1"
    local severity="$2"
    
    log "ALERT [$severity]: $message"
    
    if [[ -n "${NOTIFICATION_URL}"" ]]; then
        curl --max-time 10 --retry 3 -s -X POST "${NOTIFICATION_URL}"" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"🔐 DCOP Secret Rotation Alert [$severity]: $message\",\"severity\":\"$severity\"}" \
            || error "Failed to send alert notification"
    fi
}

# Validation de l'environnement
check_environment() {
    log "🔍 Checking environment for secret rotation..."
    
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
    
    if [[ ! -d "${SECRETS_DIR}"" ]]; then
        error "Secrets directory not found: "${SECRETS_DIR}""
        exit 1
    fi
    
    mkdir -p "${BACKUP_DIR}""
    chmod 700 "${BACKUP_DIR}""
    
    log "✅ Environment validation complete"
}

# Génération de secrets cryptographiquement sûrs
generate_secret() {
    local type="$1"
    local length="$2"
    
    case "$type" in
        "hex")
            openssl rand -hex "$length"
            ;;
        "base64")
            openssl rand -base64 "$length" | tr -d '\n'
            ;;
        "alphanumeric")
            tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$length"
            ;;
        *)
            error "Unknown secret type: $type"
            return 1
            ;;
    esac
}

# Sauvegarde des secrets actuels
backup_current_secrets() {
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_subdir="${BACKUP_DIR}"/backup_$timestamp"
    
    log "💾 Creating backup of current secrets..."
    
    mkdir -p "$backup_subdir"
    chmod 700 "$backup_subdir"
    
    cp "${SECRETS_DIR}""/*.txt "$backup_subdir/" 2>/dev/null || true
    
    # Chiffrement de la sauvegarde
    tar -czf "$backup_subdir.tar.gz" -C "$backup_subdir" .
    rm -rf "$backup_subdir"
    
    # Chiffrement avec GPG si disponible
    if command -v gpg &> /dev/null && [[ -n "${DCOP_GPG_KEY:-}" ]]; then
        gpg --trust-model always --encrypt -r "${DCOP_GPG_KEY}"" "$backup_subdir.tar.gz"
        rm "$backup_subdir.tar.gz"
        log "🔒 Backup encrypted with GPG key: "${DCOP_GPG_KEY}""
    fi
    
    log "✅ Backup created: $backup_subdir.tar.gz"
}

# Rotation du secret JWT
rotate_jwt_secret() {
    log "🔄 Rotating JWT secret..."
    
    local new_secret=$(generate_secret "hex" 64)
    echo "$new_secret" > "${SECRETS_DIR}"/jwt_secret.txt.new"
    chmod 600 "${SECRETS_DIR}"/jwt_secret.txt.new"
    
    # Validation du nouveau secret
    if [[ ${#new_secret} -eq 128 ]]; then
        mv "${SECRETS_DIR}"/jwt_secret.txt.new" "${SECRETS_DIR}"/jwt_secret.txt"
        log "✅ JWT secret rotated successfully (128 hex chars)"
    else
        error "JWT secret generation failed - invalid length"
        rm -f "${SECRETS_DIR}"/jwt_secret.txt.new"
        return 1
    fi
}

# Rotation de la clé de chiffrement
rotate_encryption_key() {
    log "🔄 Rotating encryption key..."
    
    local new_key=$(generate_secret "hex" 32)
    echo "$new_key" > "${SECRETS_DIR}"/encryption_key.txt.new"
    chmod 600 "${SECRETS_DIR}"/encryption_key.txt.new"
    
    # Validation de la nouvelle clé
    if [[ ${#new_key} -eq 64 ]]; then
        mv "${SECRETS_DIR}"/encryption_key.txt.new" "${SECRETS_DIR}"/encryption_key.txt"
        log "✅ Encryption key rotated successfully (256 bits)"
    else
        error "Encryption key generation failed - invalid length"
        rm -f "${SECRETS_DIR}"/encryption_key.txt.new"
        return 1
    fi
}

# Rotation du salt de sécurité
rotate_security_salt() {
    log "🔄 Rotating security salt..."
    
    local new_salt=$(generate_secret "hex" 32)
    echo "$new_salt" > "${SECRETS_DIR}"/security_salt.txt.new"
    chmod 600 "${SECRETS_DIR}"/security_salt.txt.new"
    
    # Validation du nouveau salt
    if [[ ${#new_salt} -eq 64 ]]; then
        mv "${SECRETS_DIR}"/security_salt.txt.new" "${SECRETS_DIR}"/security_salt.txt"
        log "✅ Security salt rotated successfully (256 bits)"
    else
        error "Security salt generation failed - invalid length"
        rm -f "${SECRETS_DIR}"/security_salt.txt.new"
        return 1
    fi
}

# Rotation du mot de passe PostgreSQL (optionnel - nécessite restart DB)
rotate_postgres_password() {
    log "🔄 Rotating PostgreSQL password..."
    
    local generated_secret
    generated_secret=$(generate_secret "base64" 32)
    echo "$generated_secret" > "${SECRETS_DIR}"/postgres_password.txt".new"
    chmod 600 "${SECRETS_DIR}"/postgres_password.txt".new"
    
    # Validation du nouveau mot de passe
    if [[ ${#generated_secret} -ge 32 ]]; then
        mv "${SECRETS_DIR}"/postgres_password.txt".new" "${SECRETS_DIR}"/postgres_password.txt""
        log "✅ PostgreSQL password rotated successfully"
        log "⚠️  WARNING: Database restart required to apply new password"
        send_alert "PostgreSQL password rotated - restart required" "WARNING"
    else
        error "PostgreSQL password generation failed - too short"
        rm -f "${SECRETS_DIR}"/postgres_password.txt".new"
        return 1
    fi
}

# Validation des secrets après rotation
validate_secrets() {
    log "🔍 Validating rotated secrets..."
    
    local errors=0
    
    # Validation JWT secret
    if [[ ! -f "${SECRETS_DIR}"/jwt_secret.txt" ]] || [[ $(wc -c < "${SECRETS_DIR}"/jwt_secret.txt") -ne 129 ]]; then
        error "JWT secret validation failed"
        ((errors++))
    fi
    
    # Validation encryption key
    if [[ ! -f "${SECRETS_DIR}"/encryption_key.txt" ]] || [[ $(wc -c < "${SECRETS_DIR}"/encryption_key.txt") -ne 65 ]]; then
        error "Encryption key validation failed"
        ((errors++))
    fi
    
    # Validation security salt
    if [[ ! -f "${SECRETS_DIR}"/security_salt.txt" ]] || [[ $(wc -c < "${SECRETS_DIR}"/security_salt.txt") -ne 65 ]]; then
        error "Security salt validation failed"
        ((errors++))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log "✅ All secrets validated successfully"
        return 0
    else
        error "Secret validation failed with $errors errors"
        return 1
    fi
}

# Nettoyage des anciennes sauvegardes
cleanup_old_backups() {
    log "🧹 Cleaning up old backups..."
    
    find "${BACKUP_DIR}"" -name "backup_*.tar.gz*" -mtime +30 -delete
    
    log "✅ Old backups cleaned up (>30 days)"
}

# Redémarrage des services (optionnel)
restart_services() {
    if [[ "${DCOP_AUTO_RESTART:-false}" == "true" ]]; then
        log "🔄 Restarting DCOP services..."
        
        systemctl restart dcop-app || docker restart dcop_app || {
            error "Failed to restart DCOP application"
            send_alert "Secret rotation completed but service restart failed" "ERROR"
            return 1
        }
        
        log "✅ Services restarted successfully"
        send_alert "Secret rotation and service restart completed successfully" "INFO"
    else
        log "⚠️  Services restart skipped (DCOP_AUTO_RESTART not enabled)"
        send_alert "Secret rotation completed - manual service restart recommended" "WARNING"
    fi
}

# Fonction principale
main() {
    log "🚀 Starting DCOP secret rotation process..."
    
    check_environment
    backup_current_secrets
    
    # Rotation des secrets
    rotate_jwt_secret
    rotate_encryption_key
    rotate_security_salt
    
    # Rotation optionnelle du mot de passe PostgreSQL
    if [[ "${DCOP_ROTATE_DB_PASSWORD:-false}" == "true" ]]; then
        rotate_postgres_password
    fi
    
    # Validation finale
    if validate_secrets; then
        log "✅ Secret rotation completed successfully"
        send_alert "Secret rotation completed successfully" "INFO"
    else
        error "Secret rotation failed validation"
        send_alert "Secret rotation failed validation" "CRITICAL"
        exit 1
    fi
    
    cleanup_old_backups
    restart_services
    
    log "🎉 DCOP secret rotation process completed"
}

# Exécution avec gestion d'erreurs
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'error "Script interrupted"; send_alert "Secret rotation interrupted" "CRITICAL"; exit 1' INT TERM
    
    main "$@"
fi
