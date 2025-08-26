#!/bin/bash
set -euo pipefail
# Script de correction temporaire des endpoints manquants

echo "🔧 DCOP (413) - Correction Endpoints via Nginx Fallback"
echo "======================================================="

# Créer un répertoire pour les endpoints temporaires
mkdir -p nginx/html/api/public/statistics
mkdir -p nginx/html/api

# Créer un endpoint temporaire pour dashboard statistics
cat > nginx/html/api/public/statistics/dashboard << 'EOF'
{
  "success": true,
  "data": {
    "active_visits": 0,
    "total_visitors": 0,
    "today_visits": 0,
    "pending_approvals": 0,
    "last_updated": "2025-08-19T16:40:00Z",
    "status": "temporary_endpoint"
  }
}
EOF

# Créer un endpoint temporaire pour visits
cat > nginx/html/api/visits << 'EOF'
{
  "success": true,
  "data": [],
  "count": 0,
  "message": "Visits endpoint temporarily served via static fallback. Please authenticate for full functionality.",
  "status": "temporary_endpoint"
}
EOF

# Ajouter la configuration de fallback dans nginx
cat >> nginx/nginx.conf << 'EOF'

        # ========================================================================
        # FALLBACK ENDPOINTS TEMPORAIRES
        # ========================================================================
        
        # Fallback pour les endpoints API manquants
        location ~ ^/api/public/statistics/dashboard$ {
            default_type application/json;
            alias /usr/share/nginx/html/api/public/statistics/dashboard;
            add_header Access-Control-Allow-Origin "*" always;
            add_header Content-Type "application/json" always;
        }
        
        location ~ ^/api/visits$ {
            default_type application/json;
            alias /usr/share/nginx/html/api/visits;
            add_header Access-Control-Allow-Origin "*" always;
            add_header Content-Type "application/json" always;
        }
        
        # Endpoint de maintenance pour diagnostic
        location = /api/status {
            default_type application/json;
            return 200 '{"status": "operational", "endpoints": {"dashboard": "fallback", "visits": "fallback"}, "timestamp": "$time_iso8601"}';
            add_header Content-Type "application/json" always;
        }
EOF

echo "✅ Endpoints temporaires créés:"
echo "📊 Dashboard: /api/public/statistics/dashboard"
echo "🏢 Visits: /api/visits"
echo "🔍 Status: /api/status"

echo ""
echo "⚠️  Ces endpoints sont temporaires et servent du JSON statique"
echo "🔄 Redémarrez Nginx pour appliquer les changements:"
echo "   docker-compose restart dcop_nginx"
