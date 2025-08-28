-- Migration pour ajouter les champs email, first_name, last_name à la table users
-- Et modifier les rôles pour correspondre au frontend
-- Ajouter les nouvelles colonnes
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS email VARCHAR(255),
ADD COLUMN IF NOT EXISTS first_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS last_name VARCHAR(100);

-- Créer un index sur l'email pour les recherches
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Mettre à jour le type ENUM pour les rôles
-- Sauvegarder d'abord les anciennes valeurs
CREATE TABLE IF NOT EXISTS temp_user_roles AS 
SELECT id, 
       CASE 
           WHEN role = 'admin' THEN 'admin'
           WHEN role = 'user' THEN 'agent'
           WHEN role = 'director' THEN 'supervisor'
           ELSE 'agent'
       END as new_role
FROM users;

-- Supprimer les contraintes sur le type ENUM
ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(20);

-- Mettre à jour les valeurs des rôles
UPDATE users SET role = (
    SELECT new_role 
    FROM temp_user_roles 
    WHERE temp_user_roles.id = users.id
);

-- Nettoyer la table temporaire
DROP TABLE IF EXISTS temp_user_roles;

-- Recréer les contraintes sur les rôles
ALTER TABLE users ADD CONSTRAINT valid_user_roles 
CHECK (role IN ('admin', 'supervisor', 'agent'));

-- Ajouter des commentaires pour documenter les changements
COMMENT ON COLUMN users.email IS 'Email address (optional)';
COMMENT ON COLUMN users.first_name IS 'First name (optional)';
COMMENT ON COLUMN users.last_name IS 'Last name (optional)';
COMMENT ON COLUMN users.role IS 'User role: admin, supervisor, or agent';
