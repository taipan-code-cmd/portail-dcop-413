-- DCOP (413) - Correction des hash de mots de passe
-- Ce script corrige les hash bcrypt invalides dans la table users

-- Mise à jour du hash pour admin (password: admin123)
UPDATE users SET password_hash = '$2b$12$f2jnSWFzQZUx1SiXZZHSbu4HjMbb6JWTUmJwh3PAQ4eCYBnL2.XG6' WHERE username = 'admin';

-- Mise à jour du hash pour user (password: user123)
UPDATE users SET password_hash = '$2b$12$VLrqc4ndvh2zgOHZudy0fedBUynNEa4A1u7iv/iinvHuIIRNTfV2G' WHERE username = 'user';

-- Mise à jour du hash pour security (password: security123)
UPDATE users SET password_hash = '$2b$12$DHR8Eh9WgH8WZj7fiBsa8e8dS38OqkxfL9THg8CFnYM5tv6G2z0z.' WHERE username = 'security';

-- Création/mise à jour de l'utilisateur admin_test (password: AdminTest123!@#)
INSERT INTO users (id, username, email, password_hash, role, is_active, failed_login_attempts, created_at, updated_at)
VALUES (
    '550e8400-e29b-41d4-a716-446655440099'::uuid,
    'admin_test',
    'admin_test@dcop413.local',
    '$2b$12$srl0YQ2e1GxM5EbwQKsqB.w9IPINzTvGLzvusrODfjbO5nQmo3OcG',
    'admin',
    true,
    0,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
)
ON CONFLICT (username) DO UPDATE SET
    password_hash = '$2b$12$srl0YQ2e1GxM5EbwQKsqB.w9IPINzTvGLzvusrODfjbO5nQmo3OcG',
    updated_at = CURRENT_TIMESTAMP;

-- Vérification - Afficher tous les utilisateurs mis à jour
SELECT username, email, role, is_active, failed_login_attempts, created_at 
FROM users 
ORDER BY created_at;

