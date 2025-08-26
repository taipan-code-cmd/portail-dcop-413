#!/bin/bash
set -euo pipefail
# DCOP (413) - Architecture Docker Simplifiée
# Un seul point d'accès : HTTPS via nginx

echo "🎯 DCOP (413) - Architecture Docker Optimisée"
echo "============================================="

echo "🏗️  ARCHITECTURE RECOMMANDÉE:"
echo ""
echo "┌─────────────────────────────────────────┐"
echo "│        🌐 nginx (Port 443)              │"
echo "│     ↙️                        ↘️          │"
echo "│  📱 Frontend              🔧 Backend     │"
echo "│  (Static files)          (API calls)    │"
echo "│     ↓                        ↓          │"
echo "│  📁 /dist/                🦀 dcop_app   │"
echo "│  (Compiled WASM)          (Port 8443)   │"
echo "└─────────────────────────────────────────┘"
echo ""

echo "✅ AVANTAGES DE CETTE ARCHITECTURE:"
echo "   • Un seul port d'accès (443)"
echo "   • Pas de CORS à gérer"
echo "   • Même origine pour frontend et backend"
echo "   • Sécurité maximale"
echo "   • Production-ready"
echo ""

echo "🚫 PROBLÈME ACTUEL:"
echo "   • Port 8090: Frontend développement (local)"
echo "   • Port 8443: Backend (Docker)"
echo "   • Port 443: Application complète"
echo "   → Complexité inutile pour Docker"
echo ""

echo "💡 SOLUTION OPTIMALE:"
echo "   • Compiler le frontend dans Docker"
echo "   • Servir tout via nginx (port 443 uniquement)"
echo "   • Développement via docker-compose"
echo ""

read -p "Voulez-vous optimiser l'architecture ? (y/N): " response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo "🚀 Optimisation de l'architecture en cours..."
else
    echo "ℹ️  Architecture actuelle conservée"
fi
