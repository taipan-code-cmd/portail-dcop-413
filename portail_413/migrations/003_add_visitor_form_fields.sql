-- Migration pour ajouter les nouveaux champs du formulaire de réception
-- Date: 2025-08-08

-- Ajouter les nouveaux champs à la table visitors
ALTER TABLE visitors 
ADD COLUMN function_encrypted TEXT,                    -- Fonction du visiteur (chiffrée, optionnelle)
ADD COLUMN visit_purpose_encrypted TEXT NOT NULL DEFAULT '', -- Objectif de la visite (chiffré, obligatoire)
ADD COLUMN host_name_encrypted TEXT,                   -- Nom de la personne à visiter (chiffré, optionnel)
ADD COLUMN visit_date VARCHAR(10),                     -- Date de la visite (format YYYY-MM-DD, non chiffrée)
ADD COLUMN visit_time VARCHAR(8),                      -- Heure prévue (format HH:MM:SS, non chiffrée)
ADD COLUMN visit_details_encrypted TEXT,               -- Détails supplémentaires (chiffrés, optionnels)

-- Engagements (checkboxes)
ADD COLUMN security_agreement BOOLEAN NOT NULL DEFAULT FALSE, -- Accord consignes de sécurité (obligatoire)
ADD COLUMN electronic_devices BOOLEAN,                 -- Interdiction appareils électroniques (optionnel)
ADD COLUMN confidentiality BOOLEAN,                    -- Engagement confidentialité (optionnel)

-- Signature
ADD COLUMN signature_date VARCHAR(10) NOT NULL DEFAULT '', -- Date de signature (obligatoire)
ADD COLUMN signature_data TEXT;                        -- Signature numérique en base64 (optionnelle)

-- Mettre à jour les enregistrements existants avec des valeurs par défaut
UPDATE visitors 
SET visit_purpose_encrypted = 'Visite non spécifiée',
    signature_date = TO_CHAR(created_at, 'YYYY-MM-DD'),
    security_agreement = TRUE
WHERE visit_purpose_encrypted = '';

-- Ajouter des commentaires pour la documentation
COMMENT ON COLUMN visitors.function_encrypted IS 'Fonction du visiteur (chiffrée AES-256-GCM)';
COMMENT ON COLUMN visitors.visit_purpose_encrypted IS 'Objectif de la visite (chiffré AES-256-GCM)';
COMMENT ON COLUMN visitors.host_name_encrypted IS 'Nom de la personne à visiter (chiffré AES-256-GCM)';
COMMENT ON COLUMN visitors.visit_date IS 'Date de la visite au format YYYY-MM-DD';
COMMENT ON COLUMN visitors.visit_time IS 'Heure prévue au format HH:MM:SS';
COMMENT ON COLUMN visitors.visit_details_encrypted IS 'Détails supplémentaires de la visite (chiffrés AES-256-GCM)';
COMMENT ON COLUMN visitors.security_agreement IS 'Accord des consignes de sécurité (obligatoire)';
COMMENT ON COLUMN visitors.electronic_devices IS 'Interdiction d''utiliser les appareils électroniques personnels';
COMMENT ON COLUMN visitors.confidentiality IS 'Engagement de confidentialité';
COMMENT ON COLUMN visitors.signature_date IS 'Date de signature au format YYYY-MM-DD';
COMMENT ON COLUMN visitors.signature_data IS 'Signature numérique en base64';

-- Créer des index pour améliorer les performances des requêtes
CREATE INDEX idx_visitors_visit_date ON visitors(visit_date) WHERE visit_date IS NOT NULL;
CREATE INDEX idx_visitors_signature_date ON visitors(signature_date);
CREATE INDEX idx_visitors_security_agreement ON visitors(security_agreement);
