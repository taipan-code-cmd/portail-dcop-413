#!/bin/bash
set -euo pipefail

# DCOP (413) - Script de Migration SQLX Durable
# Convertit toutes les macros sqlx::query! vers sqlx::query() pour éliminer les dépendances de compilation

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_DIR}""

echo "🔧 MIGRATION SQLX DURABLE - Conversion des macros"
echo "================================================="

# Fonction de logging
log_info() { echo "ℹ️  $1"; }
log_success() { echo "✅ $1"; }
log_warning() { echo "⚠️  $1"; }
log_error() { echo "❌ $1"; }

# 1. Backup des fichiers originaux
backup_dir="backup_sqlx_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$backup_dir"

log_info "Sauvegarde dans $backup_dir..."
cp -r src/ "$backup_dir/"

# 2. Conversion des requêtes par type
convert_query_macro() {
    local file="$1"
    log_info "Conversion de $file..."
    
    # Sauvegarde locale
    cp "$file" "$file.bak"
    
    # 1. sqlx::query! -> sqlx::query()
    sed -i 's/sqlx::query!/sqlx::query/g' "$file"
    
    # 2. sqlx::query_as! -> sqlx::query_as()
    sed -i 's/sqlx::query_as!/sqlx::query_as/g' "$file"
    
    # 3. sqlx::query_scalar! -> sqlx::query_scalar()
    sed -i 's/sqlx::query_scalar!/sqlx::query_scalar/g' "$file"
    
    log_success "✓ $file converti"
}

# 3. Trouver et convertir tous les fichiers Rust
log_info "Recherche des fichiers avec macros SQLX..."

files_with_macros=$(grep -r "sqlx::query\!" src/ --include="*.rs" | cut -d: -f1 | sort -u)

if [ -n "$files_with_macros" ]; then
    log_info "Fichiers trouvés avec macros SQLX:"
    echo "$files_with_macros"
    echo ""
    
    for file in $files_with_macros; do
        convert_query_macro "$file"
    done
else
    log_warning "Aucun fichier avec macros SQLX trouvé"
fi

# 4. Suppression du cache SQLX obsolète
log_info "Suppression du cache SQLX obsolète..."
rm -rf .sqlx/
log_success "Cache SQLX supprimé"

# 5. Mise à jour du Dockerfile
log_info "Mise à jour du Dockerfile..."
sed -i 's/SQLX_OFFLINE=true//g' Dockerfile
sed -i '/COPY.*\.sqlx/d' Dockerfile
log_success "Dockerfile mis à jour"

# 6. Test de compilation
log_info "Test de compilation..."
if cargo check; then
    log_success "✅ Compilation réussie sans macros SQLX !"
    
    # Suppression des backups si succès
    find . -name "*.rs.bak" -delete
    log_success "Backups temporaires supprimés"
    
else
    log_error "❌ Erreurs de compilation détectées"
    log_warning "Restauration des backups..."
    
    # Restauration des fichiers
    find . -name "*.rs.bak" | while read backup; do
        original="${backup%.bak}"
        mv "$backup" "$original"
    done
    
    log_error "Migration échouée - fichiers restaurés"
    exit 1
fi

echo ""
echo "🎉 MIGRATION SQLX DURABLE TERMINÉE !"
echo "====================================="
echo "✅ Macros SQLX converties vers requêtes simples"
echo "✅ Cache SQLX obsolète supprimé"
echo "✅ Dockerfile optimisé"
echo "✅ Compilation sans dépendance DB"
echo ""
echo "📁 Sauvegarde complète: $backup_dir/"
echo "🚀 Le projet compile maintenant de façon autonome"
