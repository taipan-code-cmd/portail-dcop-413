#!/bin/bash
set -euo pipefail

# 🔒 Générateur de secrets sécurisés DCOP-413
# Date: 26 août 2025
# Expert: Cybersecurity Specialist

set -euo pipefail

SECRETS_DIR="/home/taipan_51/portail_413/secrets"
TEMP_DIR=$(mktemp -d)

echo "🔐 Génération des secrets sécurisés..."

# 1. JWT Secret - 512 bits haute entropie
echo "Génération JWT secret..."
openssl rand -base64 64 > "${SECRETS_DIR}"/jwt_secret.txt"

# 2. PostgreSQL Password - 256 bits
echo "Génération PostgreSQL password..."
openssl rand -base64 32 | tr -d "=+/" | cut -c1-25 > "${SECRETS_DIR}"/postgres_password.txt""

# 3. Encryption Key - 256 bits AES
echo "Génération encryption key..."
openssl rand -hex 32 > "${SECRETS_DIR}"/encryption_key.txt"

# 4. Cookie Secret - 256 bits
echo "Génération cookie secret..."
openssl rand -base64 32 > "${SECRETS_DIR}"/cookie_secret.txt"

# 5. API Key interne - 128 bits
echo "Génération API key..."
openssl rand -hex 16 > "${SECRETS_DIR}"/api_key.txt"

# 6. Salt pour Argon2 - 128 bits
echo "Génération Argon2 salt..."
openssl rand -hex 16 > "${SECRETS_DIR}"/argon2_salt.txt"

# Sécurisation des permissions (owner seulement)
echo "🔒 Sécurisation des permissions..."
chmod 600 "${SECRETS_DIR}""/*.txt
chown $(whoami):$(whoami) "${SECRETS_DIR}""/*.txt

# Génération du fichier .env sécurisé
echo "📝 Génération .env sécurisé..."
cat > "${SECRETS_DIR}"/.env" << EOF
# 🔒 Variables d'environnement sécurisées DCOP-413
# ATTENTION: Ce fichier contient des secrets sensibles
# Permissions: 600 (owner seulement)

JWT_SECRET_FILE=/run/secrets/jwt_secret
POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
ENCRYPTION_KEY_FILE=/run/secrets/encryption_key
COOKIE_SECRET_FILE=/run/secrets/cookie_secret
API_KEY_FILE=/run/secrets/api_key
ARGON2_SALT_FILE=/run/secrets/argon2_salt

# Configuration de sécurité
JWT_EXPIRATION=900
SESSION_TIMEOUT=900
BCRYPT_COST=14
ARGON2_MEMORY=65536
ARGON2_ITERATIONS=3
ARGON2_PARALLELISM=4

# Base de données
POSTGRES_DB=dcop_413
POSTGRES_USER=dcop_user

# Réseau
ALLOWED_ORIGINS=https://localhost:8443,https://127.0.0.1:8443
CORS_MAX_AGE=86400

# Monitoring
ENABLE_SECURITY_LOGS=true
LOG_LEVEL=warn
EOF

chmod 600 "${SECRETS_DIR}"/.env"

# Génération du script de rotation automatique
echo "🔄 Création script de rotation..."
cat > "${SECRETS_DIR}"/rotate_secrets.sh" << 'EOF'
#!/bin/bash
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
EOF

chmod 700 "${SECRETS_DIR}"/rotate_secrets.sh"

# Vérification de l'entropie générée
echo "🧪 Vérification qualité des secrets..."
for secret_file in "${SECRETS_DIR}""/*.txt; do
    if [ -f "$secret_file" ]; then
        entropy=$(cat "$secret_file" | wc -c)
        echo "✓ $(basename "$secret_file"): $entropy caractères"
    fi
done

echo ""
echo "✅ Secrets générés avec succès!"
echo "📁 Localisation: "${SECRETS_DIR}""
echo "🔒 Permissions: 600 (owner seulement)"
echo ""
echo "📋 Prochaines étapes:"
echo "1. Vérifier les permissions: ls -la "${SECRETS_DIR}""
echo "2. Mettre à jour docker-compose.yml avec les secrets Docker"
echo "3. Redémarrer les services avec les nouveaux secrets"
echo ""
echo "⚠️  IMPORTANT: Ne jamais commiter ces fichiers dans Git!"

# Nettoyage
rm -rf "${TEMP_DIR}""
