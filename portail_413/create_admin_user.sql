-- Création d'un utilisateur admin pour les tests
INSERT INTO users (id, username, email, password_hash, role, is_active, failed_login_attempts, created_at, updated_at) 
VALUES 
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
    )
ON CONFLICT (username) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    updated_at = CURRENT_TIMESTAMP;
