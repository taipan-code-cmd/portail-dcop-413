#!/bin/bash
set -euo pipefail

# Script de démarrage rapide DCOP-413
# Auteur: GitHub Copilot
# Date: 22 août 2025

echo "🚀 DÉMARRAGE RAPIDE - PORTAIL DCOP-413"
echo "======================================"

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction d'affichage
print_step() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

# Vérification des prérequis
print_step "🔍 Vérification des prérequis..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker n'est pas installé"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose n'est pas installé" 
    exit 1
fi

print_success "Prérequis validés"

# Démarrage des services
print_step "🐳 Démarrage des services Docker..."
cd /home/taipan_51/portail_413/portail_413
docker-compose up -d

# Vérification que les services sont démarrés
print_step "⏳ Attente du démarrage des services..."
sleep 10

# Vérification de l'état des services
print_step "🔍 Vérification de l'état des services..."
docker-compose ps

# Démarrage du système backend seulement
print_step "� Système backend prêt..."
cd /home/taipan_51/portail_413

# Test de connectivité
print_step "🧪 Test de connectivité..."
sleep 3

if curl --max-time 10 --retry 3 -s http://localhost:8080 > /dev/null; then
    print_success "Serveur web accessible"
else
    echo "❌ Problème de connectivité"
    exit 1
fi

# Test de l'API
if curl --max-time 10 --retry 3 -s http://localhost:8080/api/public/statistics/dashboard > /dev/null; then
    print_success "API backend fonctionnelle"
else
    echo "❌ Problème avec l'API backend"
fi

echo ""
print_success "🎉 SYSTÈME DÉMARRÉ AVEC SUCCÈS !"
echo ""
print_info "📁 Accès au système:"
print_info "  🌐 Interface web: http://localhost:8080"
print_info "  🔐 Page de connexion: http://localhost:8080/login"
print_info "  📝 Enregistrement visite: http://localhost:8080/register-visit"
echo ""
print_info "👥 Comptes de test:"
print_info "  👑 Admin: test_admin / TestAdmin2025!@#\$%^"
print_info "  👔 Directeur: directeur / DirectorSecure2025!@#"
print_info "  👤 Admin Principal: admin / AdminDCOP2025!@#\$"
echo ""
print_info "🔧 Commandes utiles:"
print_info "  ./validation_complete_auth.sh  # Validation complète"
print_info "  docker-compose logs -f         # Voir les logs"
print_info "  docker-compose down            # Arrêter les services"
echo ""
print_success "Prêt à utiliser ! 🚀"
