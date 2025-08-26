-- Migration: Création de la table statistics pour les statistiques du système
-- Date: 2025-08-13
-- Description: Table pour stocker toutes les statistiques et métriques du système DCOP

-- Extension nécessaire pour les fonctions de hash
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS statistics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identification de la statistique
    metric_name VARCHAR(100) NOT NULL,
    metric_type VARCHAR(50) NOT NULL, -- 'daily', 'weekly', 'monthly', 'yearly', 'real_time'
    category VARCHAR(50) NOT NULL,    -- 'visits', 'users', 'security', 'system', 'performance'
    
    -- Valeurs statistiques
    value_int BIGINT DEFAULT NULL,
    value_float DECIMAL(15,4) DEFAULT NULL, 
    value_text TEXT DEFAULT NULL,
    value_json JSONB DEFAULT NULL,
    
    -- Période de référence
    period_start TIMESTAMP WITH TIME ZONE,
    period_end TIMESTAMP WITH TIME ZONE,
    reference_date DATE NOT NULL DEFAULT CURRENT_DATE,
    
    -- Métadonnées
    description TEXT,
    unit VARCHAR(20), -- 'count', 'percentage', 'minutes', 'MB', etc.
    tags TEXT[], -- Tags pour filtrage et recherche
    
    -- Audit et traçabilité
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Hash d'integrite pour la securite
    integrity_hash VARCHAR(64) NOT NULL
);

-- Index pour les performances
CREATE INDEX IF NOT EXISTS idx_statistics_metric_name ON statistics(metric_name);
CREATE INDEX IF NOT EXISTS idx_statistics_category ON statistics(category);
CREATE INDEX IF NOT EXISTS idx_statistics_metric_type ON statistics(metric_type);
CREATE INDEX IF NOT EXISTS idx_statistics_reference_date ON statistics(reference_date);
CREATE INDEX IF NOT EXISTS idx_statistics_created_at ON statistics(created_at);
CREATE INDEX IF NOT EXISTS idx_statistics_period ON statistics(period_start, period_end);

-- Index composé pour les requêtes fréquentes
CREATE INDEX IF NOT EXISTS idx_statistics_category_date ON statistics(category, reference_date);
CREATE INDEX IF NOT EXISTS idx_statistics_metric_period ON statistics(metric_name, reference_date, metric_type);

-- Trigger pour mettre à jour updated_at automatiquement
CREATE OR REPLACE FUNCTION update_statistics_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_statistics_updated_at
    BEFORE UPDATE ON statistics
    FOR EACH ROW
    EXECUTE FUNCTION update_statistics_updated_at();

-- Commentaires pour documentation
COMMENT ON TABLE statistics IS 'Table des statistiques et metriques du systeme DCOP';
COMMENT ON COLUMN statistics.metric_name IS 'Nom unique de la metrique (ex: total_visits, active_users)';
COMMENT ON COLUMN statistics.metric_type IS 'Type de periode (daily, weekly, monthly, yearly, real_time)';
COMMENT ON COLUMN statistics.category IS 'Categorie de la statistique (visits, users, security, system)';
COMMENT ON COLUMN statistics.value_int IS 'Valeur entiere de la statistique';
COMMENT ON COLUMN statistics.value_float IS 'Valeur decimale de la statistique';
COMMENT ON COLUMN statistics.value_text IS 'Valeur textuelle de la statistique';
COMMENT ON COLUMN statistics.value_json IS 'Donnees complexes JSON de la statistique';
COMMENT ON COLUMN statistics.integrity_hash IS 'Hash SHA-256 pour verifier integrite des donnees';

-- Insertion de quelques statistiques d'exemple
INSERT INTO statistics (
    metric_name, metric_type, category, value_int, reference_date, description, unit, tags, integrity_hash
) VALUES 
(
    'total_visits_today',
    'daily',
    'visits', 
    0,
    CURRENT_DATE,
    'Nombre total de visites pour aujourd hui',
    'count',
    ARRAY['visits', 'daily', 'dashboard'],
    encode(digest('total_visits_today_0_' || CURRENT_DATE::text, 'sha256'), 'hex')
),
(
    'active_visits_now',
    'real_time',
    'visits',
    0,
    CURRENT_DATE,
    'Nombre de visites actuellement en cours',
    'count',
    ARRAY['visits', 'real_time', 'dashboard'],
    encode(digest('active_visits_now_0_' || CURRENT_DATE::text, 'sha256'), 'hex')
),
(
    'total_users',
    'real_time',
    'users',
    (SELECT COUNT(*) FROM users WHERE is_active = true),
    CURRENT_DATE,
    'Nombre total d utilisateurs actifs',
    'count',
    ARRAY['users', 'total', 'dashboard'],
    encode(digest('total_users_' || (SELECT COUNT(*) FROM users WHERE is_active = true)::text || '_' || CURRENT_DATE::text, 'sha256'), 'hex')
),
(
    'total_visitors',
    'real_time',
    'visits',
    (SELECT COUNT(*) FROM visitors),
    CURRENT_DATE,
    'Nombre total de visiteurs enregistres',
    'count',
    ARRAY['visitors', 'total', 'dashboard'],
    encode(digest('total_visitors_' || (SELECT COUNT(*) FROM visitors)::text || '_' || CURRENT_DATE::text, 'sha256'), 'hex')
)
ON CONFLICT DO NOTHING;

-- Création d'une vue pour les statistiques du dashboard
CREATE OR REPLACE VIEW dashboard_statistics AS
SELECT 
    metric_name,
    category,
    COALESCE(value_int::text, value_float::text, value_text) AS display_value,
    unit,
    description,
    reference_date,
    updated_at
FROM statistics 
WHERE tags && ARRAY['dashboard']
ORDER BY category, metric_name;

COMMENT ON VIEW dashboard_statistics IS 'Vue simplifiee des statistiques pour le dashboard';
