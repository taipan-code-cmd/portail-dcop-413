#!/bin/bash
set -euo pipefail
# Rotation automatique des secrets (à exécuter mensuellement)

SECRETS_DIR="/home/taipan_51/portail_413/secrets"
BACKUP_DIR="${SECRETS_DIR}"/backup/$(date +%Y%m%d_%H%M%S)"

echo "🔄 Rotation des secrets - $(date)"

# Backup des anciens secrets
mkdir -p "${BACKUP_DIR}""
cp "${SECRETS_DIR}""/*.txt "${BACKUP_DIR}""

# Génération nouveaux secrets
openssl rand -base64 64 > "${SECRETS_DIR}"/jwt_secret.txt"
openssl rand -base64 32 | tr -d "=+/" | cut -c1-25 > "${SECRETS_DIR}"/postgres_password.txt""
openssl rand -hex 32 > "${SECRETS_DIR}"/encryption_key.txt"
openssl rand -base64 32 > "${SECRETS_DIR}"/cookie_secret.txt"
openssl rand -hex 16 > "${SECRETS_DIR}"/api_key.txt"

chmod 600 "${SECRETS_DIR}""/*.txt

echo "✅ Rotation terminée. Redémarrer les services Docker."
echo "📁 Backup stocké dans: "${BACKUP_DIR}""
