-- Add flow column to oauth_clients for authorization_code sub-flow discrimination
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS flow character varying(255) NOT NULL DEFAULT '';
