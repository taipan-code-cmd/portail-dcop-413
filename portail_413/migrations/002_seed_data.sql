-- DCOP (413) - Portail des Visites
-- Migration 002 : Données de test pour le développement et les tests
-- ATTENTION : À supprimer en production avec des données réelles

-- SÉCURITÉ : Utilisateurs de test avec mots de passe forts
-- Ces utilisateurs sont destinés UNIQUEMENT au développement et aux tests
-- ILS DOIVENT ÊTRE SUPPRIMÉS EN PRODUCTION

-- Insertion d'utilisateurs de test avec mots de passe hachés BCrypt (coût 12)
-- Mots de passe utilisés :
-- admin_test : AdminTest123!@#
-- user_test : UserTest456$%^
-- director_test : DirectorTest789&*(

INSERT INTO users (
    id,
    username,
    password_hash,
    role,
    is_active,
    last_login,
    failed_login_attempts,
    locked_until,
    created_at,
    updated_at,
    integrity_hash
) VALUES
-- Utilisateur administrateur de test
(
    '550e8400-e29b-41d4-a716-446655440001',
    'admin_test',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/VcQjiwlSe', -- AdminTest123!@#
    'admin',
    true,
    NULL,
    0,
    NULL,
    NOW(),
    NOW(),
    'temp_hash_admin'
),
-- Utilisateur standard de test
(
    '550e8400-e29b-41d4-a716-446655440002',
    'user_test',
    '$2b$12$8Xv2c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/VcQjiwlSf', -- UserTest456$%^
    'user',
    true,
    NULL,
    0,
    NULL,
    NOW(),
    NOW(),
    'temp_hash_user'
),
-- Utilisateur directeur de test
(
    '550e8400-e29b-41d4-a716-446655440003',
    'director_test',
    '$2b$12$9Yv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/VcQjiwlSg', -- DirectorTest789&*(
    'director',
    true,
    NULL,
    0,
    NULL,
    NOW(),
    NOW(),
    'temp_hash_director'
);

-- Insertion de visiteurs de test avec données chiffrées simulées
INSERT INTO visitors (
    id,
    first_name_encrypted,
    last_name_encrypted,
    email_encrypted,
    phone1_encrypted,
    phone2_encrypted,
    phone3_encrypted,
    phone4_encrypted,
    organization,
    photo_data,
    created_at,
    updated_at,
    integrity_hash
) VALUES
(
    '660e8400-e29b-41d4-a716-446655440001',
    'encrypted_jean',
    'encrypted_dupont',
    'encrypted_jean.dupont@example.com',
    'encrypted_0123456789',
    'encrypted_0987654321',
    NULL,
    NULL,
    'Entreprise Test SARL',
    NULL,
    NOW(),
    NOW(),
    'temp_hash_visitor1'
),
(
    '660e8400-e29b-41d4-a716-446655440002',
    'encrypted_marie',
    'encrypted_martin',
    'encrypted_marie.martin@example.com',
    'encrypted_0111111111',
    'encrypted_0222222222',
    'encrypted_0333333333',
    NULL,
    'Société Test SAS',
    NULL,
    NOW(),
    NOW(),
    'temp_hash_visitor2'
);

-- Insertion de visites de test
INSERT INTO visits (
    id,
    visitor_id,
    purpose,
    host_name,
    department,
    scheduled_start,
    scheduled_end,
    actual_start,
    actual_end,
    status,
    badge_number,
    notes,
    approved_by,
    approved_at,
    created_at,
    updated_at,
    integrity_hash
) VALUES
(
    '770e8400-e29b-41d4-a716-446655440001',
    '660e8400-e29b-41d4-a716-446655440001',
    'Réunion de présentation du projet',
    'Pierre Durand',
    'Direction Commerciale',
    NOW() + INTERVAL '1 day',
    NOW() + INTERVAL '1 day' + INTERVAL '2 hours',
    NULL,
    NULL,
    'pending',
    NULL,
    'Première visite - présentation générale',
    NULL,
    NULL,
    NOW(),
    NOW(),
    'temp_hash_visit1'
),
(
    '770e8400-e29b-41d4-a716-446655440002',
    '660e8400-e29b-41d4-a716-446655440002',
    'Formation technique',
    'Sophie Leblanc',
    'Service Informatique',
    NOW() + INTERVAL '2 days',
    NOW() + INTERVAL '2 days' + INTERVAL '4 hours',
    NULL,
    NULL,
    'approved',
    'BADGE001',
    'Formation sur les nouveaux outils',
    '550e8400-e29b-41d4-a716-446655440001',
    NOW(),
    NOW(),
    NOW(),
    'temp_hash_visit2'
);

-- Commentaires et documentation
COMMENT ON TABLE users IS 'Utilisateurs de test créés pour le développement - À SUPPRIMER EN PRODUCTION';

-- Message de confirmation
SELECT 'Données de test insérées avec succès - ATTENTION: À supprimer en production' as status;

-- NOTES IMPORTANTES POUR LA PRODUCTION :
-- 1. SUPPRIMER TOUS CES UTILISATEURS DE TEST
-- 2. Utiliser des mots de passe forts et uniques générés aléatoirement
-- 3. Activer l'authentification à deux facteurs si disponible
-- 4. Auditer régulièrement les comptes utilisateurs
-- 5. Implémenter une politique de rotation des mots de passe
-- 6. Les hash d'intégrité seront recalculés automatiquement par l'application
