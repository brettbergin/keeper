-- Migration: Add AES-256-GCM encryption columns to secret_versions table
-- Date: 2025-09-20
-- Description: Add nonce and auth_tag columns for AES-256-GCM encryption

-- Add new columns for AES-256-GCM
ALTER TABLE secret_versions ADD COLUMN nonce BLOB;
ALTER TABLE secret_versions ADD COLUMN auth_tag BLOB;

-- Update existing records to have empty nonce and auth_tag (for Fernet compatibility)
UPDATE secret_versions SET nonce = '', auth_tag = '' WHERE nonce IS NULL;

-- Make columns not null after setting default values
-- Note: SQLite doesn't support ALTER COLUMN, so we'll handle this in the application