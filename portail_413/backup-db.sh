#!/bin/bash
set -euo pipefail
# Script de sauvegarde automatique PostgreSQL pour DCOP (413)

echo "💾 DCOP (413) - Backup PostgreSQL Automatisé"
echo "=============================================="

# Configuration
BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="dcop_413_backup_${DATE}.sql"
CONTAINER_NAME="dcop_postgres_secure"
DB_NAME="dcop_413"
DB_USER="dcop_user"

# Créer le répertoire de sauvegarde
mkdir -p ${BACKUP_DIR}

# Fonction de sauvegarde
perform_backup() {
    echo "🔄 Démarrage de la sauvegarde..."
    
    # Vérifier que le conteneur PostgreSQL est en cours d'exécution
    if ! docker ps | grep -q ${CONTAINER_NAME}; then
        echo "❌ Erreur: Le conteneur PostgreSQL n'est pas en cours d'exécution"
        exit 1
    fi
    
    # Effectuer la sauvegarde
    docker exec -e PGPASSWORD="$(cat secrets/postgres_password.txt")" ${CONTAINER_NAME} \
        pg_dump -U ${DB_USER} -h localhost ${DB_NAME} > ${BACKUP_DIR}/${BACKUP_FILE}
    
    if [ $? -eq 0 ]; then
        echo "✅ Sauvegarde réussie: ${BACKUP_DIR}/${BACKUP_FILE}"
        
        # Compresser la sauvegarde
        gzip ${BACKUP_DIR}/${BACKUP_FILE}
        echo "🗜️  Sauvegarde compressée: ${BACKUP_DIR}/${BACKUP_FILE}.gz"
        
        # Calculer la taille
        SIZE=$(du -h ${BACKUP_DIR}/${BACKUP_FILE}.gz | cut -f1)
        echo "📊 Taille de la sauvegarde: ${SIZE}"
        
        # Nettoyer les sauvegardes anciennes (garder 7 jours)
        find ${BACKUP_DIR} -name "dcop_413_backup_*.sql.gz" -mtime +7 -delete
        echo "🧹 Anciennes sauvegardes nettoyées (>7 jours)"
        
    else
        echo "❌ Erreur lors de la sauvegarde"
        exit 1
    fi
}

# Fonction de restauration
restore_backup() {
    local backup_file=$1
    
    if [ -z "$backup_file" ]; then
        echo "❌ Erreur: Fichier de sauvegarde requis"
        echo "Usage: $0 restore <fichier_backup.sql.gz>"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        echo "❌ Erreur: Fichier de sauvegarde non trouvé: $backup_file"
        exit 1
    fi
    
    echo "🔄 Restauration depuis: $backup_file"
    
    # Décompresser si nécessaire
    if [[ $backup_file == *.gz ]]; then
        gunzip -c "$backup_file" | docker exec -i -e PGPASSWORD="$(cat secrets/postgres_password.txt")" ${CONTAINER_NAME} \
            psql -U ${DB_USER} -d ${DB_NAME}
    else
        cat "$backup_file" | docker exec -i -e PGPASSWORD="$(cat secrets/postgres_password.txt")" ${CONTAINER_NAME} \
            psql -U ${DB_USER} -d ${DB_NAME}
    fi
    
    if [ $? -eq 0 ]; then
        echo "✅ Restauration réussie"
    else
        echo "❌ Erreur lors de la restauration"
        exit 1
    fi
}

# Afficher l'utilisation
show_usage() {
    echo "Usage:"
    echo "  $0 backup          - Effectuer une sauvegarde"
    echo "  $0 restore <file>  - Restaurer depuis un fichier"
    echo "  $0 list            - Lister les sauvegardes"
    echo "  $0 status          - Afficher le statut de la base"
}

# Lister les sauvegardes
list_backups() {
    echo "📂 Sauvegardes disponibles:"
    ls -lh ${BACKUP_DIR}/dcop_413_backup_*.sql.gz 2>/dev/null | awk '{print $9, $5, $6, $7, $8}' || echo "Aucune sauvegarde trouvée"
}

# Statut de la base
show_status() {
    echo "📊 Statut de la base de données:"
    docker exec -e PGPASSWORD="$(cat secrets/postgres_password.txt")" ${CONTAINER_NAME} \
        psql -U ${DB_USER} -d ${DB_NAME} -c "
        SELECT 
            schemaname,
            relname as tablename,
            n_tup_ins as insertions,
            n_tup_upd as updates,
            n_tup_del as deletions
        FROM pg_stat_user_tables 
        ORDER BY schemaname, relname;"
}

# Menu principal
case $1 in
    backup)
        perform_backup
        ;;
    restore)
        restore_backup $2
        ;;
    list)
        list_backups
        ;;
    status)
        show_status
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
