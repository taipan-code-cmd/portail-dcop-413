-- Migration: Ajout de la contrainte unique sur statistics (metric_name, reference_date)
-- Date: 2025-08-13
-- Description: Correction pour permettre ON CONFLICT dans les requêtes d'insertion

-- D'abord, supprimons les doublons potentiels
DELETE FROM statistics s1 
WHERE s1.ctid NOT IN (
    SELECT min(s2.ctid) 
    FROM statistics s2 
    WHERE s1.metric_name = s2.metric_name 
    AND s1.reference_date = s2.reference_date
);

-- Ajouter la contrainte unique requise par le code
ALTER TABLE statistics 
ADD CONSTRAINT uk_statistics_metric_date 
UNIQUE (metric_name, reference_date);

-- Commentaire pour documentation
COMMENT ON CONSTRAINT uk_statistics_metric_date ON statistics 
IS 'Contrainte unique pour permettre ON CONFLICT dans les insertions de statistiques';
