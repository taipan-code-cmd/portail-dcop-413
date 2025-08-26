-- Migration pour créer la table statistics
-- Basée sur la structure utilisée dans statistics_repository.rs

DROP TABLE IF EXISTS statistics;

CREATE TABLE statistics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_name VARCHAR(100) NOT NULL,
    metric_type VARCHAR(50) NOT NULL, -- 'real_time', 'cumulative', 'daily', 'weekly', 'monthly'
    category VARCHAR(50) NOT NULL,    -- 'visits', 'visitors', 'security', 'system'
    value_int BIGINT,                 -- Valeurs numériques entières
    value_float DOUBLE PRECISION,     -- Valeurs numériques décimales
    value_text TEXT,                  -- Valeurs textuelles
    reference_date DATE NOT NULL,     -- Date de référence pour la métrique
    description TEXT,                 -- Description de la métrique
    unit VARCHAR(20),                 -- Unité de mesure ('count', 'percent', 'bytes', etc.)
    tags TEXT[],                      -- Tags pour catégorisation
    metadata JSONB,                   -- Métadonnées additionnelles
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    integrity_hash VARCHAR(128) NOT NULL -- Hash d'intégrité des données
);

-- Index pour améliorer les performances
CREATE INDEX idx_statistics_metric_name ON statistics(metric_name);
CREATE INDEX idx_statistics_metric_type ON statistics(metric_type);
CREATE INDEX idx_statistics_category ON statistics(category);
CREATE INDEX idx_statistics_reference_date ON statistics(reference_date);
CREATE INDEX idx_statistics_created_at ON statistics(created_at);

-- Index composite pour les requêtes fréquentes
CREATE INDEX idx_statistics_name_date ON statistics(metric_name, reference_date);
CREATE INDEX idx_statistics_category_date ON statistics(category, reference_date);

-- Contrainte d'unicité pour éviter les doublons par métrique et date
CREATE UNIQUE INDEX idx_statistics_unique_metric_date ON statistics(metric_name, reference_date);

-- Trigger pour mise à jour automatique du timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_statistics_updated_at 
    BEFORE UPDATE ON statistics 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insertion de quelques données par défaut pour les tests
INSERT INTO statistics (metric_name, metric_type, category, value_int, reference_date, description, unit, tags, integrity_hash) VALUES
('active_visits_now', 'real_time', 'visits', 0, CURRENT_DATE, 'Visites actuellement en cours', 'count', '{"visits","real_time","dashboard"}', 'd41d8cd98f00b204e9800998ecf8427e'),
('total_visitors', 'cumulative', 'visitors', 0, CURRENT_DATE, 'Total des visiteurs uniques', 'count', '{"visitors","total","dashboard"}', 'd41d8cd98f00b204e9800998ecf8427e'),
('total_visits_today', 'daily', 'visits', 0, CURRENT_DATE, 'Visites créées aujourd''hui', 'count', '{"visits","daily","dashboard"}', 'd41d8cd98f00b204e9800998ecf8427e'),
('pending_approvals', 'real_time', 'visits', 0, CURRENT_DATE, 'Demandes d''approbation en attente', 'count', '{"visits","pending","dashboard"}', 'd41d8cd98f00b204e9800998ecf8427e');

-- Vérification de la table créée
SELECT table_name, column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'statistics' 
ORDER BY ordinal_position;
