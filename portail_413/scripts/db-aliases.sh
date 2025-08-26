#!/bin/bash
set -euo pipefail

# DCOP (413) - Alias et raccourcis pour la base de données
# Source ce fichier dans votre .bashrc : source /path/to/db-aliases.sh

# Répertoire du projet
DCOP_PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Alias pour le gestionnaire de mot de passe
alias dcop-db="${DCOP_PROJECT_DIR}"/scripts/db-password-manager.sh"
alias dcop-pwd="${DCOP_PROJECT_DIR}"/scripts/get-db-password.sh"

# Alias pour les commandes courantes
alias dcop-db-show="${DCOP_PROJECT_DIR}"/scripts/db-password-manager.sh show"
alias dcop-db-copy="${DCOP_PROJECT_DIR}"/scripts/db-password-manager.sh copy"
alias dcop-db-connect="${DCOP_PROJECT_DIR}"/scripts/db-password-manager.sh connect"
alias dcop-db-test="${DCOP_PROJECT_DIR}"/scripts/db-password-manager.sh test"
alias dcop-db-sqlx="${DCOP_PROJECT_DIR}"/scripts/db-password-manager.sh sqlx"

# Fonction pour exécuter des requêtes SQL rapidement
dcop-sql() {
    if [[ $# -eq 0 ]]; then
        echo "Usage: dcop-sql \"SELECT ...\""
        return 1
    fi
    "${DCOP_PROJECT_DIR}"/scripts/db-password-manager.sh" sql "$1"
}

# Fonction pour se connecter avec psql directement
dcop-psql() {
    local password=$("${DCOP_PROJECT_DIR}"/scripts/get-db-password.sh")
    export PGPASSWORD="$password"
    psql -h localhost -p 5432 -U dcop_user -d dcop_413 "$@"
}

# Fonction pour charger l'environnement DCOP
dcop-env() {
    cd "${DCOP_PROJECT_DIR}""
    if [[ -f ".env" ]]; then
        source .env
        echo "✅ Environnement DCOP chargé"
        echo "📁 Répertoire : "${PWD}""
        echo "🗄️  DATABASE_URL : "${DATABASE_URL}""
    else
        echo "❌ Fichier .env non trouvé"
    fi
}

echo "🔐 Alias DCOP (413) chargés :"
echo "   dcop-db [commande]     - Gestionnaire de mot de passe"
echo "   dcop-pwd               - Afficher le mot de passe"
echo "   dcop-db-show           - Afficher les infos de connexion"
echo "   dcop-db-copy           - Copier le mot de passe"
echo "   dcop-db-connect        - Se connecter à PostgreSQL"
echo "   dcop-db-test           - Tester la connexion"
echo "   dcop-db-sqlx           - Générer le cache SQLx"
echo "   dcop-sql \"SELECT...\"   - Exécuter une requête SQL"
echo "   dcop-psql              - Connexion psql directe"
echo "   dcop-env               - Charger l'environnement"
