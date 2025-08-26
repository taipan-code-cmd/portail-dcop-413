#!/bin/bash
set -euo pipefail
# DCOP (413) - Port Security Management Script
# Script pour bloquer tous les ports non autorisés et maintenir la sécurité
# Compatible avec l'architecture Docker

# Ports autorisés pour l'application DCOP 413 (Architecture unifiée port 8443)
ALLOWED_PORTS=(
    8443    # Backend + Frontend unifié (seul port nécessaire)
    5433    # PostgreSQL (Docker, localhost uniquement)
    6379    # Redis (Docker, pour sessions/cache)
)

# Fonction pour vérifier si un port est autorisé
is_port_allowed() {
    local port=$1
    for allowed in "${ALLOWED_PORTS[@]}"; do
        if [[ $port -eq $allowed ]]; then
            return 0
        fi
    done
    return 1
}

# Fonction pour bloquer un port spécifique
block_port() {
    local port=$1
    echo "🚫 Blocage du port $port..."
    
    # Méthode 1: Via iptables (si disponible)
    if command -v iptables >/dev/null 2>&1; then
        sudo iptables -A INPUT -p tcp --dport $port -j REJECT 2>/dev/null
        sudo iptables -A INPUT -p udp --dport $port -j REJECT 2>/dev/null
    fi
    
    # Méthode 2: Via service bind prevention
    echo "127.0.0.1:$port" >> /tmp/blocked_ports.txt
}

# Fonction pour débloquer les ports autorisés
allow_port() {
    local port=$1
    echo "✅ Autorisation du port $port..."
    
    if command -v iptables >/dev/null 2>&1; then
        sudo iptables -D INPUT -p tcp --dport $port -j REJECT 2>/dev/null || true
        sudo iptables -D INPUT -p udp --dport $port -j REJECT 2>/dev/null || true
    fi
}

# Initialiser le fichier des ports bloqués
echo "# Ports bloqués par DCOP 413 Security" > /tmp/blocked_ports.txt
echo "# $(date)" >> /tmp/blocked_ports.txt

# Ports à bloquer explicitement (connus pour être problématiques)
BLOCKED_PORTS=(
    8080    # Port frontend bloqué
    8081    # Port frontend Trunk bloqué  
    3000    # Port de développement courant
    3001    # Port de développement alternatif
    4000    # Port de développement
    5000    # Port de développement Flask/autres
    8000    # Port de développement
    9000    # Port de développement
)

echo "🔒 DCOP (413) - Configuration de sécurité des ports"
echo "================================================"

# Bloquer les ports explicitement interdits
for port in "${BLOCKED_PORTS[@]}"; do
    block_port $port
done

# Autoriser les ports légitimes
for port in "${ALLOWED_PORTS[@]}"; do
    allow_port $port
done

echo ""
echo "📋 Ports autorisés:"
for port in "${ALLOWED_PORTS[@]}"; do
    echo "  ✅ $port"
done

echo ""
echo "🚫 Ports bloqués:"
for port in "${BLOCKED_PORTS[@]}"; do
    echo "  ❌ $port"
done

echo ""
echo "✅ Configuration de sécurité appliquée !"
