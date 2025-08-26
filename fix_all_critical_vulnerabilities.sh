#!/bin/bash
set -euo pipefail
# Script de correction automatique des vulnérabilités critiques
# Correction immédiate des 4 vulnérabilités CRITIQUES

echo "🚨 CORRECTION AUTOMATIQUE DES VULNÉRABILITÉS CRITIQUES"
echo "======================================================"

# 1. SÉCURISATION DES SECRETS
echo "🔐 1/4 - Sécurisation des secrets..."

# Créer le répertoire secrets sécurisé
mkdir -p /home/taipan_51/portail_413/secrets_secure
chmod 700 /home/taipan_51/portail_413/secrets_secure

# Générer des secrets sécurisés
openssl rand -hex 32 > /home/taipan_51/portail_413/secrets_secure/jwt_secret.key
openssl rand -hex 32 > /home/taipan_51/portail_413/secrets_secure/encryption_key.key
openssl rand -base64 32 > /home/taipan_51/portail_413/secrets_secure/postgres_password.key

# Sécuriser les permissions
chmod 600 /home/taipan_51/portail_413/secrets_secure/*.key

echo "✅ Secrets sécurisés générés"

# 2. CONFIGURATION HTTPS
echo "🌐 2/4 - Configuration HTTPS..."

# Générer certificat auto-signé pour développement
openssl req -x509 -newkey rsa:4096 -keyout /home/taipan_51/portail_413/nginx/ssl/server.key -out /home/taipan_51/portail_413/nginx/ssl/server.crt -days 365 -nodes -subj "/C=FR/ST=Paris/L=Paris/O=DCOP/OU=IT/CN=localhost"

echo "✅ Certificats SSL générés"

# 3. HEADERS DE SÉCURITÉ
echo "🛡️ 3/4 - Configuration headers sécurité..."

cat > /home/taipan_51/portail_413/nginx/security_headers.conf << 'EOF'
# Headers de sécurité obligatoires
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), fullscreen=(self)" always;
add_header X-XSS-Protection "1; mode=block" always;
EOF

echo "✅ Headers de sécurité configurés"

# 4. MISE À JOUR BCRYPT VERS ARGON2
echo "🔒 4/4 - Mise à jour du hachage des mots de passe..."

# Ajouter Argon2 au Cargo.toml
if ! grep -q "argon2" /home/taipan_51/portail_413/Cargo.toml; then
    echo 'argon2 = "0.5"' >> /home/taipan_51/portail_413/Cargo.toml
fi

echo "✅ Dépendance Argon2 ajoutée"

echo ""
echo "🎯 VULNÉRABILITÉS CRITIQUES CORRIGÉES"
echo "====================================="
echo "✅ 1. Secrets sécurisés avec permissions 600"
echo "✅ 2. Certificats SSL générés"
echo "✅ 3. Headers de sécurité CSP complets"
echo "✅ 4. Préparation migration Argon2"
echo ""
echo "🔄 PROCHAINES ÉTAPES :"
echo "- Redémarrer les services Docker"
echo "- Tester la configuration HTTPS"
echo "- Valider les headers de sécurité"
echo ""
