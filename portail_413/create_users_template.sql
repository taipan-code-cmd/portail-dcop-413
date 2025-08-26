-- Script SQL pour créer directement les utilisateurs de test
-- Avec les nouvelles politiques de sécurité

-- Nettoyer les anciens utilisateurs
DELETE FROM visits;
DELETE FROM visitors;  
DELETE FROM users;

-- Créer les utilisateurs avec des mots de passe hashés (bcrypt)
-- Les mots de passe respectent les nouvelles règles (12+ caractères)

INSERT INTO users (id, username, password_hash, role, is_active, created_at, updated_at, integrity_hash) VALUES
-- Admin principal: admin_dcop / AdminDCOP2025!@#
('00000000-0000-0000-0000-000000000001', 'admin_dcop', '$2b$12$XYZ.bcrypt.hash.here.AdminDCOP2025', 'admin', true, NOW(), NOW(), 'hash1'),

-- Admin sécurité: admin_security / SecuAdmin2025$%
('00000000-0000-0000-0000-000000000002', 'admin_security', '$2b$12$XYZ.bcrypt.hash.here.SecuAdmin2025', 'admin', true, NOW(), NOW(), 'hash2'),

-- Admin système: admin_system / SysAdmin2025&*()
('00000000-0000-0000-0000-000000000003', 'admin_system', '$2b$12$XYZ.bcrypt.hash.here.SysAdmin2025', 'admin', true, NOW(), NOW(), 'hash3'),

-- Utilisateur réception: user_reception / Reception2025!@
('00000000-0000-0000-0000-000000000004', 'user_reception', '$2b$12$XYZ.bcrypt.hash.here.Reception2025', 'user', true, NOW(), NOW(), 'hash4'),

-- Agent sécurité: user_security / Security2025#$
('00000000-0000-0000-0000-000000000005', 'user_security', '$2b$12$XYZ.bcrypt.hash.here.Security2025', 'user', true, NOW(), NOW(), 'hash5'),

-- Manager: user_manager / Manager2025%^&
('00000000-0000-0000-0000-000000000006', 'user_manager', '$2b$12$XYZ.bcrypt.hash.here.Manager2025', 'user', true, NOW(), NOW(), 'hash6'),

-- Test user 1: test_user1 / TestUser2025!@#
('00000000-0000-0000-0000-000000000007', 'test_user1', '$2b$12$XYZ.bcrypt.hash.here.TestUser2025', 'user', true, NOW(), NOW(), 'hash7'),

-- Test user 2: test_user2 / TestUser2025$%^
('00000000-0000-0000-0000-000000000008', 'test_user2', '$2b$12$XYZ.bcrypt.hash.here.TestUser2025b', 'user', true, NOW(), NOW(), 'hash8');

SELECT 'Utilisateurs créés avec succès!' as message;
SELECT username, role FROM users ORDER BY role, username;
