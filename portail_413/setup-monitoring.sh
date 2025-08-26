#!/bin/bash
set -euo pipefail
# Script de setup monitoring avancé pour DCOP (413)

echo "🔍 DCOP (413) - Configuration Monitoring Avancé"
echo "================================================="

# Créer un répertoire de monitoring
mkdir -p monitoring/prometheus
mkdir -p monitoring/grafana

# Configuration Prometheus basic
cat > monitoring/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'dcop-app'
    static_configs:
      - targets: ['dcop_app:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s
    
  - job_name: 'nginx'
    static_configs:
      - targets: ['dcop_nginx:80']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['dcop_postgres_secure:5432']
    scrape_interval: 15s
EOF

# Configuration Grafana dashboard
cat > monitoring/grafana/dashboard.json << 'EOF'
{
  "dashboard": {
    "title": "DCOP (413) - System Monitor",
    "panels": [
      {
        "title": "Active Visits",
        "type": "stat"
      },
      {
        "title": "Database Connections",
        "type": "graph"
      },
      {
        "title": "HTTP Requests",
        "type": "graph"
      }
    ]
  }
}
EOF

echo "✅ Configuration monitoring créée dans monitoring/"
echo "📊 Prometheus config: monitoring/prometheus/prometheus.yml"
echo "📈 Grafana dashboard: monitoring/grafana/dashboard.json"
