-- Script SQL pour créer des utilisateurs avec mots de passe conformes aux nouvelles règles
-- Utilise le système de hachage interne de PostgreSQL compatible avec bcrypt

-- Fonction pour générer un hash d'intégrité simple
CREATE OR REPLACE FUNCTION generate_simple_integrity_hash(username text) 
RETURNS VARCHAR(128) AS $$
BEGIN
    RETURN encode(digest(username || 'dcop-integrity-salt-2025', 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Corriger d'abord le hash corrompu de 'utilisateur'
UPDATE users 
SET password_hash = crypt('UtilisateurSecure2025!@#', gen_salt('bf', 12)),
    updated_at = NOW()
WHERE username = 'utilisateur';

-- Créer des utilisateurs de test avec mots de passe conformes (12+ caractères)

-- Administrateurs sécurisés
INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'admin_secure', crypt('AdminSecure2025!@#$', gen_salt('bf', 12)), 'admin', true, 0, NOW(), NOW(), generate_simple_integrity_hash('admin_secure'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('AdminSecure2025!@#$', gen_salt('bf', 12)),
    updated_at = NOW();

INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'admin_test_new', crypt('AdminTest2025!@#$%', gen_salt('bf', 12)), 'admin', true, 0, NOW(), NOW(), generate_simple_integrity_hash('admin_test_new'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('AdminTest2025!@#$%', gen_salt('bf', 12)),
    updated_at = NOW();

-- Directeurs sécurisés
INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'directeur_secure', crypt('DirectorSecure2025!@#', gen_salt('bf', 12)), 'director', true, 0, NOW(), NOW(), generate_simple_integrity_hash('directeur_secure'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('DirectorSecure2025!@#', gen_salt('bf', 12)),
    updated_at = NOW();

INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'director_new', crypt('DirectorNew2025$%^&', gen_salt('bf', 12)), 'director', true, 0, NOW(), NOW(), generate_simple_integrity_hash('director_new'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('DirectorNew2025$%^&', gen_salt('bf', 12)),
    updated_at = NOW();

-- Utilisateurs sécurisés
INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'user_secure', crypt('UserSecure2025!@#$', gen_salt('bf', 12)), 'user', true, 0, NOW(), NOW(), generate_simple_integrity_hash('user_secure'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('UserSecure2025!@#$', gen_salt('bf', 12)),
    updated_at = NOW();

INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'agent_secure', crypt('AgentSecure2025#$%^', gen_salt('bf', 12)), 'user', true, 0, NOW(), NOW(), generate_simple_integrity_hash('agent_secure'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('AgentSecure2025#$%^', gen_salt('bf', 12)),
    updated_at = NOW();

INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'reception_secure', crypt('Reception2025!@#$%', gen_salt('bf', 12)), 'user', true, 0, NOW(), NOW(), generate_simple_integrity_hash('reception_secure'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('Reception2025!@#$%', gen_salt('bf', 12)),
    updated_at = NOW();

-- Utilisateurs de test principaux
INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'test_admin', crypt('TestAdmin2025!@#$%^', gen_salt('bf', 12)), 'admin', true, 0, NOW(), NOW(), generate_simple_integrity_hash('test_admin'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('TestAdmin2025!@#$%^', gen_salt('bf', 12)),
    updated_at = NOW();

INSERT INTO users (id, username, password_hash, role, is_active, failed_login_attempts, created_at, updated_at, integrity_hash)
VALUES 
    (uuid_generate_v4(), 'test_user', crypt('TestUser2025!@#$%^&', gen_salt('bf', 12)), 'user', true, 0, NOW(), NOW(), generate_simple_integrity_hash('test_user'))
ON CONFLICT (username) DO UPDATE SET
    password_hash = crypt('TestUser2025!@#$%^&', gen_salt('bf', 12)),
    updated_at = NOW();

-- Afficher le résumé
SELECT 
    'UTILISATEURS CRÉÉS AVEC SUCCÈS' as message;

SELECT 
    username,
    role,
    is_active,
    created_at
FROM users 
WHERE username IN (
    'admin_secure', 'admin_test_new', 'directeur_secure', 'director_new',
    'user_secure', 'agent_secure', 'reception_secure', 'test_admin', 'test_user',
    'utilisateur'
)
ORDER BY role, username;

SELECT 'COMPTES DE TEST RECOMMANDÉS:' as info;
