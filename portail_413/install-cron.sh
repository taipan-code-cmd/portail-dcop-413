#!/bin/bash
set -euo pipefail
echo "Installation des tâches cron DCOP (413)..."
crontab dcop_cron_jobs
echo "✅ Tâches cron installées"
echo "📋 Vérification:"
crontab -l | grep DCOP
