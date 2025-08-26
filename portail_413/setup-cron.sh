#!/bin/bash
set -euo pipefail
# Script d'installation du cron automatique pour DCOP (413)

echo "⏰ DCOP (413) - Configuration Sauvegarde Automatique"
echo "===================================================="

# Chemin absolu vers le script de backup
SCRIPT_PATH="$(pwd)/backup-db.sh"
HEALTH_PATH="$(pwd)/health-check.sh"

# Créer une entrée cron pour la sauvegarde quotidienne à 2h du matin
echo "📅 Configuration des tâches automatiques..."

# Créer le fichier cron temporaire
cat > dcop_cron_jobs << EOF
# DCOP (413) - Tâches automatiques
# Sauvegarde quotidienne à 2h00
0 2 * * * cd $(pwd) && "${SCRIPT_PATH}" backup >> logs/backup.log 2>&1

# Vérification de santé toutes les heures
0 * * * * cd $(pwd) && "${HEALTH_PATH}" >> logs/health.log 2>&1

# Nettoyage des logs anciens tous les dimanches à 3h00
0 3 * * 0 find $(pwd)/logs -name "*.log" -mtime +30 -delete

EOF

# Créer le répertoire de logs s'il n'existe pas
mkdir -p logs

echo "📝 Tâches cron configurées:"
echo "• Sauvegarde quotidienne: 2h00"
echo "• Vérification santé: toutes les heures"
echo "• Nettoyage logs: dimanche 3h00"
echo ""

echo "🔧 Pour activer les tâches automatiques, exécutez:"
echo "   crontab dcop_cron_jobs"
echo ""
echo "📂 Logs seront dans: $(pwd)/logs/"
echo "   - backup.log: Logs des sauvegardes"
echo "   - health.log: Logs des vérifications"

# Créer un script d'installation
cat > install-cron.sh << 'EOF'
#!/bin/bash
echo "Installation des tâches cron DCOP (413)..."
crontab dcop_cron_jobs
echo "✅ Tâches cron installées"
echo "📋 Vérification:"
crontab -l | grep DCOP
EOF

chmod +x install-cron.sh

echo ""
echo "⚡ Installation rapide:"
echo "   ./install-cron.sh"
