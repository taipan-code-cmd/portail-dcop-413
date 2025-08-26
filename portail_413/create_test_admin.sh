#!/bin/bash
set -euo pipefail

# Script pour créer un utilisateur admin de test
# Se connecte directement à PostgreSQL pour insérer un utilisateur

DB_HOST="localhost"
DB_PORT="5433"
DB_NAME="dcop_413"
DB_USER="dcop_user"
DB_PASSWORD="EhbcQDl6bcvRPvEgFtr2O6cOuQdAuTMmpO3XkLNMqMw="

# Générer un hash bcrypt pour le mot de passe AdminDCOP2025!@#
PASSWORD_HASH='$2b$12"${LQ}"v3c1yqBwEHXk.kQ7KjBOK5C8gXQ3zF.mQ.kQqGqGYH3K.kF8Fme'

echo "Création d'un utilisateur admin de test..."

PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" << EOF
INSERT INTO users (id, username, password_hash, role, is_active, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    'admin_dcop',
    '"${PASSWORD_HASH}"',
    'admin',
    true,
    NOW(),
    NOW()
) ON CONFLICT (username) DO NOTHING;

-- Vérifier que l'utilisateur a été créé
SELECT id, username, role, is_active, created_at FROM users WHERE username = 'admin_dcop';
EOF

echo "Utilisateur admin créé/vérifié avec succès !"
