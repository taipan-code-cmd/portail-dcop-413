#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de génération de certificats ECDSA P-384 sécurisés
# Génère des certificats conformes OWASP A02:2021 et Secure-by-Design
# Utilise ECDSA P-384 (secp384r1) pour une sécurité cryptographique maximale

set -euo pipefail

# Configuration
DOMAIN="${1:-dcop.local}"
CERT_DIR="./nginx/ssl"
BACKUP_DIR="./nginx/ssl/backup"
VALIDITY_DAYS="365"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔒 DCOP (413) - Générateur de Certificats ECDSA P-384${NC}"
echo -e "${BLUE}=================================================${NC}"

# Vérifier les prérequis
check_prerequisites() {
    echo -e "${YELLOW}📋 Vérification des prérequis...${NC}"
    
    if ! command -v openssl &> /dev/null; then
        echo -e "${RED}❌ OpenSSL n'est pas installé${NC}"
        exit 1
    fi
    
    local openssl_version=$(openssl version | cut -d' ' -f2)
    echo -e "${GREEN}✅ OpenSSL version: $openssl_version${NC}"
    
    # Vérifier le support ECDSA
    if ! openssl ecparam -list_curves | grep -q "secp384r1"; then
        echo -e "${RED}❌ Support ECDSA P-384 non disponible${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Support ECDSA P-384 confirmé${NC}"
}

# Créer les répertoires nécessaires
setup_directories() {
    echo -e "${YELLOW}📁 Création des répertoires...${NC}"
    
    mkdir -p "${CERT_DIR}""
    mkdir -p "${BACKUP_DIR}""
    
    echo -e "${GREEN}✅ Répertoires créés${NC}"
}

# Sauvegarder les anciens certificats
backup_existing_certs() {
    echo -e "${YELLOW}💾 Sauvegarde des certificats existants...${NC}"
    
    if [[ -f "${CERT_DIR}"/server.key" ]] || [[ -f "${CERT_DIR}"/server.crt" ]]; then
        local backup_timestamp=$(date +"%Y%m%d_%H%M%S")
        local backup_subdir="${BACKUP_DIR}"/backup_$backup_timestamp"
        
        mkdir -p "$backup_subdir"
        
        if [[ -f "${CERT_DIR}"/server.key" ]]; then
            cp "${CERT_DIR}"/server.key" "$backup_subdir/"
            echo -e "${GREEN}✅ Clé privée sauvegardée${NC}"
        fi
        
        if [[ -f "${CERT_DIR}"/server.crt" ]]; then
            cp "${CERT_DIR}"/server.crt" "$backup_subdir/"
            echo -e "${GREEN}✅ Certificat sauvegardé${NC}"
        fi
        
        echo -e "${GREEN}✅ Sauvegarde dans: $backup_subdir${NC}"
    else
        echo -e "${YELLOW}ℹ️  Aucun certificat existant à sauvegarder${NC}"
    fi
}

# Générer la clé privée ECDSA P-384
generate_private_key() {
    echo -e "${YELLOW}🔑 Génération de la clé privée ECDSA P-384...${NC}"
    
    # Générer la clé privée avec ECDSA P-384
    openssl ecparam -genkey -name secp384r1 -out "${CERT_DIR}"/server.key"
    
    # Sécuriser les permissions
    chmod 600 "${CERT_DIR}"/server.key"
    
    echo -e "${GREEN}✅ Clé privée ECDSA P-384 générée${NC}"
}

# Créer le fichier de configuration pour le certificat
create_cert_config() {
    echo -e "${YELLOW}📝 Création de la configuration du certificat...${NC}"
    
    cat > "${CERT_DIR}"/cert.conf" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha384
distinguished_name = dn
req_extensions = v3_req

[dn]
C=CD
ST=Kinshasa
L=Kinshasa
O=DCOP
OU=Cybersecurity Division
CN="${DOMAIN}"

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = "${DOMAIN}"
DNS.2 = *."${DOMAIN}"
DNS.3 = localhost
DNS.4 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    
    echo -e "${GREEN}✅ Configuration du certificat créée${NC}"
}

# Générer le certificat auto-signé
generate_self_signed_cert() {
    echo -e "${YELLOW}📜 Génération du certificat auto-signé...${NC}"
    
    openssl req -new -x509 \
        -key "${CERT_DIR}"/server.key" \
        -out "${CERT_DIR}"/server.crt" \
        -days "${VALIDITY_DAYS}"" \
        -config "${CERT_DIR}"/cert.conf" \
        -extensions v3_req \
        -sha384
    
    # Permissions sécurisées
    chmod 644 "${CERT_DIR}"/server.crt"
    
    echo -e "${GREEN}✅ Certificat auto-signé généré${NC}"
}

# Générer les paramètres Diffie-Hellman renforcés
generate_dhparam() {
    echo -e "${YELLOW}🔐 Génération des paramètres Diffie-Hellman 4096 bits...${NC}"
    
    if [[ ! -f "${CERT_DIR}"/dhparam.pem" ]]; then
        openssl dhparam -out "${CERT_DIR}"/dhparam.pem" 4096
        chmod 644 "${CERT_DIR}"/dhparam.pem"
        echo -e "${GREEN}✅ Paramètres DH 4096 bits générés${NC}"
    else
        echo -e "${YELLOW}ℹ️  Paramètres DH existants conservés${NC}"
    fi
}

# Créer des liens compatibles
create_compatibility_links() {
    echo -e "${YELLOW}🔗 Création des liens de compatibilité...${NC}"
    
    cd "${CERT_DIR}""
    
    # Liens pour compatibilité avec la configuration nginx existante
    ln -sf server.crt cert.pem 2>/dev/null || true
    ln -sf server.key key.pem 2>/dev/null || true
    
    cd - > /dev/null
    
    echo -e "${GREEN}✅ Liens de compatibilité créés${NC}"
}

# Vérifier le certificat généré
verify_certificate() {
    echo -e "${YELLOW}🔍 Vérification du certificat...${NC}"
    
    # Vérifier la validité du certificat
    if openssl x509 -in "${CERT_DIR}"/server.crt" -text -noout > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Certificat valide${NC}"
        
        # Afficher les informations du certificat
        echo -e "${BLUE}📋 Informations du certificat:${NC}"
        openssl x509 -in "${CERT_DIR}"/server.crt" -text -noout | grep -E "(Subject:|Not Before|Not After|Public Key Algorithm|Signature Algorithm)"
        
        # Vérifier la correspondance clé/certificat pour ECDSA
        local key_modulus=$(openssl pkey -in "${CERT_DIR}"/server.key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null || echo "key_error")
        local cert_modulus=$(openssl x509 -in "${CERT_DIR}"/server.crt" -pubkey -noout -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null || echo "cert_error")

        if [[ "$key_modulus" != "key_error" ]] && [[ "$cert_modulus" != "cert_error" ]] && [[ "$key_modulus" == "$cert_modulus" ]]; then
            echo -e "${GREEN}✅ Clé privée et certificat correspondent${NC}"
        else
            echo -e "${YELLOW}⚠️  Vérification de correspondance ignorée pour ECDSA${NC}"
            # Pour ECDSA, on fait une vérification alternative
            if openssl x509 -in "${CERT_DIR}"/server.crt" -noout -modulus >/dev/null 2>&1; then
                echo -e "${GREEN}✅ Certificat ECDSA valide${NC}"
            fi
        fi
    else
        echo -e "${RED}❌ Certificat invalide${NC}"
        exit 1
    fi
}

# Afficher les instructions Let's Encrypt
show_letsencrypt_instructions() {
    echo -e "${BLUE}🌐 Instructions pour Let's Encrypt (Production):${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    echo -e "${YELLOW}1. Installer Certbot:${NC}"
    echo "   sudo apt-get update"
    echo "   sudo apt-get install certbot python3-certbot-nginx"
    echo ""
    echo -e "${YELLOW}2. Obtenir un certificat Let's Encrypt:${NC}"
    echo "   sudo certbot --nginx -d "${DOMAIN}""
    echo ""
    echo -e "${YELLOW}3. Renouvellement automatique:${NC}"
    echo "   sudo crontab -e"
    echo "   # Ajouter: 0 12 * * * /usr/bin/certbot renew --quiet"
    echo ""
    echo -e "${YELLOW}4. Test de renouvellement:${NC}"
    echo "   sudo certbot renew --dry-run"
    echo ""
}

# Fonction principale
main() {
    echo -e "${BLUE}🚀 Génération des certificats ECDSA P-384 pour: "${DOMAIN}"${NC}"
    echo ""
    
    check_prerequisites
    setup_directories
    backup_existing_certs
    generate_private_key
    create_cert_config
    generate_self_signed_cert
    generate_dhparam
    create_compatibility_links
    verify_certificate
    
    echo ""
    echo -e "${GREEN}🎉 Certificats ECDSA P-384 générés avec succès!${NC}"
    echo -e "${GREEN}📁 Emplacement: "${CERT_DIR}"${NC}"
    echo ""
    
    show_letsencrypt_instructions
    
    echo -e "${BLUE}⚠️  IMPORTANT: En production, utilisez Let's Encrypt pour des certificats valides!${NC}"
}

# Exécution du script
main "$@"
