#!/bin/bash
set -euo pipefail

# DCOP (413) - Générateur d'utilisateurs de test avec mots de passe hachés BCrypt
# Génère des hash BCrypt corrects pour les utilisateurs de test

set -euo pipefail

# Configuration
BCRYPT_COST=12

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

# Vérification des prérequis
check_prerequisites() {
    log "Vérification des prérequis..."
    
    if ! command -v python3 &> /dev/null; then
        error "Python3 n'est pas installé"
        exit 1
    fi
    
    # Vérifier si bcrypt est disponible
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        log "Installation de bcrypt..."
        pip3 install bcrypt || {
            error "Impossible d'installer bcrypt. Installez-le manuellement : pip3 install bcrypt"
            exit 1
        }
    fi
    
    success "Prérequis validés"
}

# Génération des hash BCrypt
generate_bcrypt_hashes() {
    log "Génération des hash BCrypt pour les utilisateurs de test..."
    
    # Créer le script Python pour générer les hash
    cat > /tmp/generate_hashes.py << EOF
import bcrypt
import sys

def hash_password(password, cost="${BCRYPT_COST}"):
    "Hash un mot de passe avec BCrypt"
    salt = bcrypt.gensalt(rounds=cost)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password, hashed):
    "Vérifie un mot de passe contre son hash"
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Mots de passe de test (forts et sécurisés)
test_passwords = {
    'admin_test': 'AdminTest123!@#',
    'user_test': 'UserTest456\$%^',
    'director_test': 'DirectorTest789&*('
}

print("=== Hash BCrypt générés (coût "${BCRYPT_COST}") ===")
print()

for username, password in test_passwords.items():
    hashed = hash_password(password)
    
    # Vérification
    if verify_password(password, hashed):
        print(f"✓ {username}:")
        print(f"  Mot de passe: {password}")
        print(f"  Hash BCrypt: {hashed}")
        print()
    else:
        print(f"✗ Erreur lors de la génération du hash pour {username}")
        sys.exit(1)

print("=== Vérification des hash ===")
for username, password in test_passwords.items():
    hashed = hash_password(password)
    if verify_password(password, hashed):
        print(f"✓ {username}: Hash valide")
    else:
        print(f"✗ {username}: Hash invalide")
        sys.exit(1)

print()
print("Tous les hash ont été générés et vérifiés avec succès !")
EOF

    # Exécuter le script Python
    python3 /tmp/generate_hashes.py
    
    # Nettoyer
    rm /tmp/generate_hashes.py
    
    success "Hash BCrypt générés avec succès"
}

# Mise à jour du fichier de migration avec les vrais hash
update_migration_file() {
    log "Mise à jour du fichier de migration avec les hash corrects..."
    
    # Générer les hash et les capturer
    cat > /tmp/get_hashes.py << EOF
import bcrypt

def hash_password(password, cost="${BCRYPT_COST}"):
    salt = bcrypt.gensalt(rounds=cost)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# Générer les hash
admin_hash = hash_password('AdminTest123!@#')
user_hash = hash_password('UserTest456\$%^')
director_hash = hash_password('DirectorTest789&*(')

print(f"ADMIN_HASH={admin_hash}")
print(f"USER_HASH={user_hash}")
print(f"DIRECTOR_HASH={director_hash}")
EOF

    # Capturer les hash
    eval $(python3 /tmp/get_hashes.py)
    
    # Backup du fichier de migration
    cp ../migrations/002_seed_data.sql ../migrations/002_seed_data.sql.backup
    
    # Remplacer les hash temporaires par les vrais hash
    sed -i "s/\$2b\$12\"${LQ}"v3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8\/LewdBPj\/VcQjiwlSe/${ADMIN_HASH//\//\\/}/g" ../migrations/002_seed_data.sql
    sed -i "s/\$2b\$12\$8Xv2c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8\/LewdBPj\/VcQjiwlSf/${USER_HASH//\//\\/}/g" ../migrations/002_seed_data.sql
    sed -i "s/\$2b\$12\$9Yv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8\/LewdBPj\/VcQjiwlSg/${DIRECTOR_HASH//\//\\/}/g" ../migrations/002_seed_data.sql
    
    # Nettoyer
    rm /tmp/get_hashes.py
    
    success "Fichier de migration mis à jour avec les hash corrects"
    warning "Backup sauvegardé dans migrations/002_seed_data.sql.backup"
}

# Création d'un script de test des utilisateurs
create_test_script() {
    log "Création du script de test des utilisateurs..."
    
    cat > ../scripts/test-auth.sh << 'EOF'
#!/bin/bash

# Script de test de l'authentification avec les utilisateurs de test

set -euo pipefail

API_BASE="https://localhost:8443/api"
CURL_OPTS="-k -s -w \n%{http_code}\n"

echo "=== Test d'authentification des utilisateurs de test ==="
echo

# Test admin
echo "Test utilisateur admin_test..."
RESPONSE=$(curl "${CURL_OPTS}" -X POST "${API_BASE}"/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin_test","password":"AdminTest123!@#"}')

HTTP_CODE=$(echo "${RESPONSE}"" | tail -n1)
BODY=$(echo "${RESPONSE}"" | head -n -1)

if [ "${HTTP_CODE}"" = "200" ]; then
    echo "✓ Admin login réussi"
    echo "Response: "${BODY}""
else
    echo "✗ Admin login échoué (HTTP "${HTTP_CODE}")"
    echo "Response: "${BODY}""
fi

echo

# Test user
echo "Test utilisateur user_test..."
RESPONSE=$(curl "${CURL_OPTS}" -X POST "${API_BASE}"/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"user_test","password":"UserTest456$%^"}')

HTTP_CODE=$(echo "${RESPONSE}"" | tail -n1)
BODY=$(echo "${RESPONSE}"" | head -n -1)

if [ "${HTTP_CODE}"" = "200" ]; then
    echo "✓ User login réussi"
    echo "Response: "${BODY}""
else
    echo "✗ User login échoué (HTTP "${HTTP_CODE}")"
    echo "Response: "${BODY}""
fi

echo

# Test director
echo "Test utilisateur director_test..."
RESPONSE=$(curl "${CURL_OPTS}" -X POST "${API_BASE}"/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"director_test","password":"DirectorTest789&*("}')

HTTP_CODE=$(echo "${RESPONSE}"" | tail -n1)
BODY=$(echo "${RESPONSE}"" | head -n -1)

if [ "${HTTP_CODE}"" = "200" ]; then
    echo "✓ Director login réussi"
    echo "Response: "${BODY}""
else
    echo "✗ Director login échoué (HTTP "${HTTP_CODE}")"
    echo "Response: "${BODY}""
fi

echo
echo "=== Tests terminés ==="
EOF

    chmod +x ../scripts/test-auth.sh
    
    success "Script de test créé : scripts/test-auth.sh"
}

# Affichage des informations de connexion
show_test_credentials() {
    echo ""
    echo "=== INFORMATIONS DE CONNEXION POUR LES TESTS ==="
    echo ""
    echo "🔐 Utilisateurs de test créés :"
    echo ""
    echo "1. Administrateur :"
    echo "   Username: admin_test"
    echo "   Password: AdminTest123!@#"
    echo "   Role: admin"
    echo ""
    echo "2. Utilisateur standard :"
    echo "   Username: user_test"
    echo "   Password: UserTest456\$%^"
    echo "   Role: user"
    echo ""
    echo "3. Directeur :"
    echo "   Username: director_test"
    echo "   Password: DirectorTest789&*("
    echo "   Role: director"
    echo ""
    echo "⚠️  ATTENTION : Ces utilisateurs sont destinés UNIQUEMENT aux tests"
    echo "⚠️  ILS DOIVENT ÊTRE SUPPRIMÉS EN PRODUCTION"
    echo ""
    echo "📝 Pour tester l'authentification :"
    echo "   ./scripts/test-auth.sh"
    echo ""
}

# Fonction principale
main() {
    log "Génération des utilisateurs de test avec hash BCrypt"
    
    check_prerequisites
    generate_bcrypt_hashes
    update_migration_file
    create_test_script
    show_test_credentials
    
    success "Génération terminée avec succès !"
    echo ""
    echo "Prochaines étapes :"
    echo "1. Appliquer les migrations : docker-compose exec dcop_app sqlx migrate run"
    echo "2. Tester l'authentification : ./scripts/test-auth.sh"
    echo "3. Supprimer ces utilisateurs en production"
}

# Exécution du script
main "$@"
