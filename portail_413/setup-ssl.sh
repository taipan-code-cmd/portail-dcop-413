#!/bin/bash
set -euo pipefail
# Script de génération de certificats SSL pour DCOP (413)

echo "🔐 DCOP (413) - Génération Certificats SSL/TLS"
echo "==============================================="

# Créer le répertoire SSL s'il n'existe pas
mkdir -p nginx/ssl

# Générer une clé privée
openssl genrsa -out nginx/ssl/dcop.key 2048

# Générer un certificat auto-signé valide 365 jours
openssl req -new -x509 -key nginx/ssl/dcop.key -out nginx/ssl/dcop.crt -days 365 -subj "/C=FR/ST=France/L=Paris/O=DCOP413/OU=IT/CN=localhost"

# Générer des paramètres Diffie-Hellman forts
openssl dhparam -out nginx/ssl/dhparam.pem 2048

# Créer la configuration SSL pour Nginx
cat > nginx/ssl.conf << 'EOF'
# Configuration SSL/TLS sécurisée pour DCOP (413)

ssl_certificate /etc/nginx/ssl/dcop.crt;
ssl_certificate_key /etc/nginx/ssl/dcop.key;
ssl_dhparam /etc/nginx/ssl/dhparam.pem;

# Protocoles SSL/TLS modernes uniquement
ssl_protocols TLSv1.2 TLSv1.3;

# Ciphers sécurisés priorité aux courbes elliptiques
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Session SSL
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
EOF

echo "✅ Certificats SSL générés:"
echo "🔑 Clé privée: nginx/ssl/dcop.key"
echo "📜 Certificat: nginx/ssl/dcop.crt"
echo "🔒 DH Params: nginx/ssl/dhparam.pem"
echo "⚙️  Config SSL: nginx/ssl.conf"

# Vérifier les permissions
chmod 600 nginx/ssl/dcop.key
chmod 644 nginx/ssl/dcop.crt
chmod 644 nginx/ssl/dhparam.pem

echo "🔐 Permissions de sécurité appliquées"
