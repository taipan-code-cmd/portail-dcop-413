-- DCOP (413) - Portail des Visites
-- Migration initiale : Création des tables principales
-- Avec chiffrement, hachage d'intégrité et audit complet

-- Extensions nécessaires
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Création d'un utilisateur avec privilèges minimaux pour l'application
-- Remplace dcop_user qui avait des privilèges de superutilisateur
DO $$
BEGIN
    -- Créer l'utilisateur app_user s'il n'existe pas
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
        CREATE USER app_user WITH PASSWORD 'temp_password_to_change';
    END IF;

    -- Révoquer tous les privilèges par défaut
    REVOKE ALL ON DATABASE dcop_413 FROM app_user;
    REVOKE ALL ON SCHEMA public FROM app_user;

    -- Accorder uniquement les privilèges nécessaires
    GRANT CONNECT ON DATABASE dcop_413 TO app_user;
    GRANT USAGE ON SCHEMA public TO app_user;
END
$$;

-- Types énumérés
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'user', 'director');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE visit_status AS ENUM ('pending', 'approved', 'rejected', 'inprogress', 'completed', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Table des utilisateurs avec sécurité renforcée
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, -- Hash Argon2id
    role user_role NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_login TIMESTAMPTZ,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    integrity_hash VARCHAR(128) NOT NULL -- SHA-512 pour vérification d'intégrité
);

-- Table des visiteurs avec données chiffrées
CREATE TABLE IF NOT EXISTS visitors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    first_name_encrypted TEXT NOT NULL, -- Chiffré AES-256-GCM
    last_name_encrypted TEXT NOT NULL,  -- Chiffré AES-256-GCM
    email_encrypted TEXT,               -- Chiffré AES-256-GCM (optionnel)
    phone1_encrypted TEXT NOT NULL,     -- Téléphone principal (obligatoire, chiffré)
    phone2_encrypted TEXT NOT NULL,     -- Téléphone secondaire (obligatoire, chiffré)
    phone3_encrypted TEXT,              -- Téléphone tertiaire (optionnel, chiffré)
    phone4_encrypted TEXT,              -- Téléphone quaternaire (optionnel, chiffré)
    organization VARCHAR(200) NOT NULL,
    photo_data TEXT,                    -- Photo en base64
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    integrity_hash VARCHAR(128) NOT NULL -- SHA-512 pour vérification d'intégrité
);

-- Table des visites
CREATE TABLE IF NOT EXISTS visits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    visitor_id UUID NOT NULL REFERENCES visitors(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    host_name VARCHAR(100) NOT NULL,
    department VARCHAR(100) NOT NULL,
    scheduled_start TIMESTAMPTZ NOT NULL,
    scheduled_end TIMESTAMPTZ NOT NULL,
    actual_start TIMESTAMPTZ,
    actual_end TIMESTAMPTZ,
    status visit_status NOT NULL DEFAULT 'pending',
    badge_number VARCHAR(20) UNIQUE,
    notes TEXT,
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    integrity_hash VARCHAR(128) NOT NULL -- SHA-512 pour vérification d'intégrité
);

-- Table d'audit pour traçabilité complète
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT
);

-- Index pour les performances et la sécurité
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_users_locked_until ON users(locked_until);

CREATE INDEX idx_visitors_organization ON visitors(organization);
CREATE INDEX idx_visitors_created_at ON visitors(created_at);

CREATE INDEX idx_visits_visitor_id ON visits(visitor_id);
CREATE INDEX idx_visits_status ON visits(status);
CREATE INDEX idx_visits_scheduled_start ON visits(scheduled_start);
CREATE INDEX idx_visits_department ON visits(department);
CREATE INDEX idx_visits_badge_number ON visits(badge_number);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_success ON audit_logs(success);

-- Triggers pour mise à jour automatique des timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_visitors_updated_at BEFORE UPDATE ON visitors
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_visits_updated_at BEFORE UPDATE ON visits
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Contraintes de sécurité renforcées
ALTER TABLE users ADD CONSTRAINT chk_username_length CHECK (length(username) >= 3 AND length(username) <= 50);
ALTER TABLE users ADD CONSTRAINT chk_failed_attempts CHECK (failed_login_attempts >= 0 AND failed_login_attempts <= 10);
ALTER TABLE users ADD CONSTRAINT chk_username_format CHECK (username ~ '^[a-zA-Z0-9_.-]+$');

ALTER TABLE visitors ADD CONSTRAINT chk_organization_length CHECK (length(organization) >= 2 AND length(organization) <= 200);

ALTER TABLE visits ADD CONSTRAINT chk_scheduled_dates CHECK (scheduled_end > scheduled_start);
ALTER TABLE visits ADD CONSTRAINT chk_actual_dates CHECK (actual_end IS NULL OR actual_start IS NULL OR actual_end >= actual_start);
ALTER TABLE visits ADD CONSTRAINT chk_purpose_length CHECK (length(purpose) >= 5);
ALTER TABLE visits ADD CONSTRAINT chk_host_name_length CHECK (length(host_name) >= 2 AND length(host_name) <= 100);
ALTER TABLE visits ADD CONSTRAINT chk_department_length CHECK (length(department) >= 2 AND length(department) <= 100);

-- Politique de sécurité au niveau ligne (RLS) - Activée pour la sécurité
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitors ENABLE ROW LEVEL SECURITY;
ALTER TABLE visits ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Commentaires pour documentation
COMMENT ON TABLE users IS 'Table des utilisateurs du système avec authentification sécurisée';
COMMENT ON TABLE visitors IS 'Table des visiteurs avec données personnelles chiffrées';
COMMENT ON TABLE visits IS 'Table des visites avec suivi complet du cycle de vie';
COMMENT ON TABLE audit_logs IS 'Table d''audit pour traçabilité complète des actions';

COMMENT ON COLUMN users.password_hash IS 'Hash Argon2id du mot de passe';
COMMENT ON COLUMN users.integrity_hash IS 'Hash SHA-512 pour vérification d''intégrité des données';
COMMENT ON COLUMN visitors.first_name_encrypted IS 'Prénom chiffré avec AES-256-GCM';
COMMENT ON COLUMN visitors.last_name_encrypted IS 'Nom chiffré avec AES-256-GCM';
COMMENT ON COLUMN visitors.phone1_encrypted IS 'Téléphone principal (obligatoire) chiffré avec AES-256-GCM';
COMMENT ON COLUMN visitors.phone2_encrypted IS 'Téléphone secondaire (obligatoire) chiffré avec AES-256-GCM';
COMMENT ON COLUMN visitors.phone3_encrypted IS 'Téléphone tertiaire (optionnel) chiffré avec AES-256-GCM';
COMMENT ON COLUMN visitors.phone4_encrypted IS 'Téléphone quaternaire (optionnel) chiffré avec AES-256-GCM';

-- Attribution des privilèges minimaux à app_user après création des tables
DO $$
BEGIN
    -- Privilèges sur les tables
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;

    -- Privilèges sur les séquences (pour les UUID et auto-increment)
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;

    -- Privilèges sur les fonctions (pour les triggers)
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO app_user;

    -- Privilèges par défaut pour les futures tables/séquences
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_user;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO app_user;
END
$$;
