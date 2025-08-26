#!/bin/bash
set -euo pipefail

# DCOP (413) - Configuration Let's Encrypt pour certificats SSL valides
# Remplace les certificats auto-signés par des certificats Let's Encrypt

set -euo pipefail

# Configuration
DOMAIN="${1:-}"
EMAIL="${2:-}"
NGINX_CONTAINER="dcop_nginx"
CERTBOT_CONTAINER="certbot"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'affichage
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Affichage de l'aide
show_help() {
    echo "Usage: $0 <domain> <email>"
    echo ""
    echo "Paramètres:"
    echo "  domain    Nom de domaine pour le certificat SSL (ex: dcop.example.com)"
    echo "  email     Adresse email pour Let's Encrypt (ex: admin@example.com)"
    echo ""
    echo "Exemple:"
    echo "  $0 dcop.example.com admin@example.com"
}

# Validation des paramètres
validate_params() {
    if [[ -z "${DOMAIN}"" || -z "${EMAIL}"" ]]; then
        error "Paramètres manquants"
        show_help
        exit 1
    fi
    
    # Validation basique du format email
    if [[ ! "${EMAIL}"" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        error "Format d'email invalide: "${EMAIL}""
        exit 1
    fi
    
    # Validation basique du domaine
    if [[ ! "${DOMAIN}"" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        error "Format de domaine invalide: "${DOMAIN}""
        exit 1
    fi
}

# Vérification des prérequis
check_prerequisites() {
    log "Vérification des prérequis..."
    
    if ! command -v docker &> /dev/null; then
        error "Docker n'est pas installé ou accessible"
        exit 1
    fi
    
    if ! docker ps | grep -q "${NGINX_CONTAINER}""; then
        error "Le conteneur Nginx '"${NGINX_CONTAINER}"' n'est pas en cours d'exécution"
        exit 1
    fi
    
    # Vérifier que le domaine pointe vers ce serveur
    log "Vérification DNS pour "${DOMAIN}"..."
    SERVER_IP=$(curl --max-time 10 --retry 3 -s ifconfig.me || echo "unknown")
    DOMAIN_IP=$(dig +short "${DOMAIN}"" | tail -n1)
    
    if [[ "${SERVER_IP}"" != "${DOMAIN_IP}"" ]]; then
        warning "Le domaine "${DOMAIN}" ne semble pas pointer vers ce serveur"
        warning "IP du serveur: "${SERVER_IP}""
        warning "IP du domaine: "${DOMAIN_IP}""
        read -p "Continuer quand même ? (y/N): " -n 1 -r
        echo
        if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    success "Prérequis validés"
}

# Création de la configuration Nginx temporaire pour le challenge
create_temp_nginx_config() {
    log "Création de la configuration Nginx temporaire..."
    
    cat > ../nginx/nginx-letsencrypt.conf << EOF
events {
    worker_connections 1024;
}

http {
    server {
        listen 80;
        server_name "${DOMAIN}";
        
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
        
        location / {
            return 301 https://\$server_name\$request_uri;
        }
    }
}
EOF
    
    success "Configuration temporaire créée"
}

# Obtention du certificat Let's Encrypt
obtain_certificate() {
    log "Obtention du certificat Let's Encrypt pour "${DOMAIN}"..."
    
    # Créer les répertoires nécessaires
    mkdir -p ../nginx/certbot/www
    mkdir -p ../nginx/certbot/conf
    
    # Arrêter Nginx temporairement
    docker stop "${NGINX_CONTAINER}"" || true
    
    # Démarrer Nginx avec la configuration temporaire
    docker run -d --name nginx-temp \
        -p 80:80 \
        -v "$(pwd)/../nginx/nginx-letsencrypt.conf:/etc/nginx/nginx.conf:ro" \
        -v "$(pwd)/../nginx/certbot/www:/var/www/certbot:rw" \
        nginx:alpine
    
    # Obtenir le certificat avec Certbot
    docker run --rm \
        -v "$(pwd)/../nginx/certbot/conf:/etc/letsencrypt:rw" \
        -v "$(pwd)/../nginx/certbot/www:/var/www/certbot:rw" \
        certbot/certbot \
        certonly \
        --webroot \
        --webroot-path=/var/www/certbot \
        --email "${EMAIL}"" \
        --agree-tos \
        --no-eff-email \
        -d "${DOMAIN}""
    
    # Arrêter Nginx temporaire
    docker stop nginx-temp
    docker rm nginx-temp
    
    success "Certificat obtenu avec succès"
}

# Mise à jour de la configuration Nginx pour utiliser Let's Encrypt
update_nginx_config() {
    log "Mise à jour de la configuration Nginx..."
    
    # Backup de la configuration actuelle
    cp ../nginx/nginx.conf ../nginx/nginx.conf.backup
    
    # Créer la nouvelle configuration avec Let's Encrypt
    cat > ../nginx/nginx.conf << EOF
# DCOP (413) - Configuration Nginx avec Let's Encrypt
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logs
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;
    
    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    # Sécurité
    server_tokens off;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Redirection HTTP vers HTTPS
    server {
        listen 80;
        server_name "${DOMAIN}";
        
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
        
        location / {
            return 301 https://\$server_name\$request_uri;
        }
    }
    
    # Configuration HTTPS avec Let's Encrypt
    server {
        listen 443 ssl http2;
        server_name "${DOMAIN}";
        
        # Certificats Let's Encrypt
        ssl_certificate /etc/letsencrypt/live/"${DOMAIN}"/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/"${DOMAIN}"/privkey.pem;
        
        # Configuration SSL moderne
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        
        # OCSP Stapling
        ssl_stapling on;
        ssl_stapling_verify on;
        ssl_trusted_certificate /etc/letsencrypt/live/"${DOMAIN}"/chain.pem;
        
        # Proxy vers l'application
        location / {
            include /etc/nginx/proxy_params_secure.conf;
            proxy_pass http://dcop_app:8443;
        }
    }
}
EOF
    
    success "Configuration Nginx mise à jour"
}

# Mise à jour du docker-compose pour Let's Encrypt
update_docker_compose() {
    log "Mise à jour du docker-compose.yml..."
    
    # Backup
    cp ../docker-compose.yml ../docker-compose.yml.letsencrypt-backup
    
    # Ajouter les volumes pour Let's Encrypt dans la section nginx
    sed -i '/nginx_cache:\/var\/cache\/nginx:rw/a\      - ./nginx/certbot/conf:/etc/letsencrypt:ro\n      - ./nginx/certbot/www:/var/www/certbot:rw' ../docker-compose.yml
    
    success "docker-compose.yml mis à jour"
}

# Configuration du renouvellement automatique
setup_auto_renewal() {
    log "Configuration du renouvellement automatique..."
    
    # Créer le script de renouvellement
    cat > ../scripts/renew-certificates.sh << 'EOF'
#!/bin/bash
# Script de renouvellement automatique des certificats Let's Encrypt

docker run --rm \
    -v "$(pwd)/nginx/certbot/conf:/etc/letsencrypt:rw" \
    -v "$(pwd)/nginx/certbot/www:/var/www/certbot:rw" \
    certbot/certbot \
    renew \
    --quiet

# Recharger Nginx si le renouvellement a réussi
if [ $? -eq 0 ]; then
    docker exec dcop_nginx nginx -s reload
fi
EOF
    
    chmod +x ../scripts/renew-certificates.sh
    
    # Ajouter une tâche cron (optionnel)
    echo "# Renouvellement automatique des certificats Let's Encrypt (tous les jours à 2h)"
    echo "0 2 * * * cd /path/to/portail_413 && ./scripts/renew-certificates.sh"
    
    success "Renouvellement automatique configuré"
}

# Fonction principale
main() {
    log "Configuration Let's Encrypt pour "${DOMAIN}""
    
    validate_params
    check_prerequisites
    create_temp_nginx_config
    obtain_certificate
    update_nginx_config
    update_docker_compose
    setup_auto_renewal
    
    success "Configuration Let's Encrypt terminée !"
    echo ""
    echo "Prochaines étapes :"
    echo "1. Redémarrer Nginx : docker-compose restart nginx"
    echo "2. Vérifier le certificat : https://"${DOMAIN}""
    echo "3. Configurer le renouvellement automatique dans cron"
}

# Exécution du script
main "$@"
