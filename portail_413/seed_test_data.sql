-- DCOP (413) - Script de Seeding pour Tests
-- Création d'utilisateurs et données de test pour valider les corrections

-- Insertion des utilisateurs de test avec différents rôles
INSERT INTO users (id, username, email, password_hash, role, is_active, failed_login_attempts, created_at, updated_at) 
VALUES 
    -- Administrateur de test
    (
        '550e8400-e29b-41d4-a716-446655440001'::uuid,
        'admin',
        'admin@dcop413.local',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfBFm0.Bf8LNVVG', -- password: admin123
        'admin',
        true,
        0,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    
    -- Utilisateur standard de test  
    (
        '550e8400-e29b-41d4-a716-446655440002'::uuid,
        'user',
        'user@dcop413.local', 
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfBFm0.Bf8LNVVG', -- password: user123
        'user',
        true,
        0,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),

    -- Utilisateur de sécurité de test
    (
        '550e8400-e29b-41d4-a716-446655440003'::uuid,
        'security',
        'security@dcop413.local',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfBFm0.Bf8LNVVG', -- password: security123  
        'security',
        true,
        0,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),

    -- Utilisateur désactivé pour tests de sécurité
    (
        '550e8400-e29b-41d4-a716-446655440004'::uuid,
        'disabled_user',
        'disabled@dcop413.local',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewfBFm0.Bf8LNVVG', -- password: disabled123
        'user',
        false, -- Utilisateur désactivé
        0,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    )
ON CONFLICT (username) DO NOTHING;

-- Insertion de visiteurs de test (données chiffrées simulées)
INSERT INTO visitors (id, first_name_encrypted, last_name_encrypted, email_encrypted, phone1_encrypted, phone2_encrypted, organization, created_at, updated_at, integrity_hash)
VALUES 
    (
        '660e8400-e29b-41d4-a716-446655440001'::uuid,
        'encrypted_john', -- Simulé: "John" chiffré
        'encrypted_doe', -- Simulé: "Doe" chiffré  
        'encrypted_john.doe@example.com', -- Simulé: email chiffré
        'encrypted_+33123456789', -- Simulé: téléphone chiffré
        'encrypted_+33987654321', -- Simulé: téléphone 2 chiffré
        'Test Corporation',
        CURRENT_TIMESTAMP - INTERVAL '7 days',
        CURRENT_TIMESTAMP - INTERVAL '7 days',
        'test_hash_1'
    ),
    
    (
        '660e8400-e29b-41d4-a716-446655440002'::uuid,
        'encrypted_jane',
        'encrypted_smith',
        'encrypted_jane.smith@company.fr',
        'encrypted_+33456789123',
        'encrypted_+33789123456',
        'Secure Industries',
        CURRENT_TIMESTAMP - INTERVAL '3 days',
        CURRENT_TIMESTAMP - INTERVAL '3 days', 
        'test_hash_2'
    )
ON CONFLICT (id) DO NOTHING;

-- Insertion de visites de test
INSERT INTO visits (id, visitor_id, purpose, start_time, end_time, status, host_name, notes, created_by, created_at, updated_at, integrity_hash)
VALUES 
    (
        '770e8400-e29b-41d4-a716-446655440001'::uuid,
        '660e8400-e29b-41d4-a716-446655440001'::uuid,
        'Réunion de sécurité',
        CURRENT_TIMESTAMP - INTERVAL '2 hours',
        CURRENT_TIMESTAMP - INTERVAL '1 hour',
        'completed',
        'Agent Sécurité',
        'Visite de contrôle standard',
        '550e8400-e29b-41d4-a716-446655440003'::uuid, -- Créé par security user
        CURRENT_TIMESTAMP - INTERVAL '2 hours',
        CURRENT_TIMESTAMP - INTERVAL '1 hour',
        'visit_hash_1'
    ),
    
    (
        '770e8400-e29b-41d4-a716-446655440002'::uuid,
        '660e8400-e29b-41d4-a716-446655440002'::uuid,
        'Audit technique',
        CURRENT_TIMESTAMP - INTERVAL '30 minutes',
        NULL, -- Visite en cours
        'in_progress',
        'Responsable IT',
        'Audit de sécurité informatique',
        '550e8400-e29b-41d4-a716-446655440001'::uuid, -- Créé par admin
        CURRENT_TIMESTAMP - INTERVAL '30 minutes',
        CURRENT_TIMESTAMP - INTERVAL '30 minutes',
        'visit_hash_2'
    )
ON CONFLICT (id) DO NOTHING;

-- Insertion d'entrées d'audit pour les tests
INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, old_values, new_values, ip_address, user_agent, created_at, integrity_hash)
VALUES 
    (
        '880e8400-e29b-41d4-a716-446655440001'::uuid,
        '550e8400-e29b-41d4-a716-446655440001'::uuid,
        'login',
        'user',
        '550e8400-e29b-41d4-a716-446655440001'::uuid,
        NULL,
        '{"login_time": "' || CURRENT_TIMESTAMP || '"}',
        '127.0.0.1',
        'Test-User-Agent/1.0',
        CURRENT_TIMESTAMP - INTERVAL '1 hour',
        'audit_hash_1'
    ),
    
    (
        '880e8400-e29b-41d4-a716-446655440002'::uuid,
        '550e8400-e29b-41d4-a716-446655440003'::uuid,
        'create',
        'visit',
        '770e8400-e29b-41d4-a716-446655440001'::uuid,
        NULL,
        '{"purpose": "Réunion de sécurité", "visitor_id": "660e8400-e29b-41d4-a716-446655440001"}',
        '172.25.1.10',
        'Security-Agent/2.0',
        CURRENT_TIMESTAMP - INTERVAL '2 hours',
        'audit_hash_2'
    )
ON CONFLICT (id) DO NOTHING;

-- Message de confirmation
SELECT 'Données de test insérées avec succès!' as status,
       (SELECT COUNT(*) FROM users WHERE username LIKE '%admin%' OR username LIKE '%user%' OR username LIKE '%security%') as users_count,
       (SELECT COUNT(*) FROM visitors WHERE organization LIKE '%Test%' OR organization LIKE '%Secure%') as visitors_count,
       (SELECT COUNT(*) FROM visits WHERE purpose LIKE '%sécurité%' OR purpose LIKE '%Audit%') as visits_count,
       (SELECT COUNT(*) FROM audit_logs WHERE user_agent LIKE '%Test%' OR user_agent LIKE '%Security%') as audit_count;
