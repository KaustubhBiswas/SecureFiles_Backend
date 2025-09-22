-- Idempotent Migration Script - Safe to run multiple times
-- This will only create tables/indexes that don't already exist

-- Enable UUID extension if not exists
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ========== USERS TABLE ==========
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'USER', -- USER, ADMIN, PREMIUM
    quota_limit BIGINT NOT NULL DEFAULT 104857600, -- 10MB default
    quota_used BIGINT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- ========== BLOBS TABLE (Content Storage) ==========
-- Create the table first, then add columns if needed
CREATE TABLE IF NOT EXISTS blobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA-256 hash
    size_bytes BIGINT NOT NULL
);

-- Add ALL required columns to existing blobs table
DO $$
BEGIN
    -- Add created_at column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'blobs' AND column_name = 'created_at'
    ) THEN
        ALTER TABLE blobs ADD COLUMN created_at TIMESTAMP WITH TIME ZONE DEFAULT now();
    END IF;
    
    -- Add mime_type column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'blobs' AND column_name = 'mime_type'
    ) THEN
        ALTER TABLE blobs ADD COLUMN mime_type VARCHAR(255);
    END IF;
    
    -- Add s3_key column if it doesn't exist (without column reference in DEFAULT)
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'blobs' AND column_name = 's3_key'
    ) THEN
        ALTER TABLE blobs ADD COLUMN s3_key TEXT;
        -- Update existing rows with a generated s3_key
        UPDATE blobs SET s3_key = 'legacy/' || id::text WHERE s3_key IS NULL;
        -- Now make it NOT NULL
        ALTER TABLE blobs ALTER COLUMN s3_key SET NOT NULL;
        -- Set default for new rows
        ALTER TABLE blobs ALTER COLUMN s3_key SET DEFAULT 'legacy-key';
    END IF;
    
    -- Add s3_bucket column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'blobs' AND column_name = 's3_bucket'
    ) THEN
        ALTER TABLE blobs ADD COLUMN s3_bucket VARCHAR(255) NOT NULL DEFAULT 'kaustubhbalkanid';
    END IF;
    
    -- Add upload_status column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'blobs' AND column_name = 'upload_status'
    ) THEN
        ALTER TABLE blobs ADD COLUMN upload_status VARCHAR(50) NOT NULL DEFAULT 'UPLOADED';
    END IF;
    
    -- Add uploaded_at column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'blobs' AND column_name = 'uploaded_at'
    ) THEN
        ALTER TABLE blobs ADD COLUMN uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now();
    END IF;
    
    -- Add deleted_at column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'blobs' AND column_name = 'deleted_at'
    ) THEN
        ALTER TABLE blobs ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE;
    END IF;
END $$;

-- ========== FOLDERS TABLE (Optional Hierarchy) ==========
CREATE TABLE IF NOT EXISTS folders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    parent_folder_id UUID REFERENCES folders(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Add unique constraint if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'folders_name_parent_owner_key'
    ) THEN
        ALTER TABLE folders ADD CONSTRAINT folders_name_parent_owner_key 
        UNIQUE(name, parent_folder_id, owner_id);
    END IF;
END $$;

-- ========== FILES TABLE (File Metadata) ==========
CREATE TABLE IF NOT EXISTS files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL, -- User's original filename
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id UUID REFERENCES folders(id) ON DELETE CASCADE, -- NULL = root folder
    is_public BOOLEAN NOT NULL DEFAULT false,
    description TEXT,
    tags TEXT[] DEFAULT '{}', -- Array of tags for searching
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    deleted_at TIMESTAMP WITH TIME ZONE -- Soft delete
);

-- Add S3-specific columns to existing files table
DO $$
BEGIN
    -- Add blob_id column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'files' AND column_name = 'blob_id'
    ) THEN
        ALTER TABLE files ADD COLUMN blob_id UUID REFERENCES blobs(id) ON DELETE RESTRICT;
    END IF;
    
    -- Add file_size column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'files' AND column_name = 'file_size'
    ) THEN
        ALTER TABLE files ADD COLUMN file_size BIGINT NOT NULL DEFAULT 0;
    END IF;
    
    -- Add download_count column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'files' AND column_name = 'download_count'
    ) THEN
        ALTER TABLE files ADD COLUMN download_count INTEGER DEFAULT 0;
    END IF;
END $$;

-- ========== DOWNLOADS TABLE (Download Tracking) ==========
CREATE TABLE IF NOT EXISTS downloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    downloaded_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    download_size BIGINT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'COMPLETED'
);

-- Add missing columns to downloads table
DO $$
BEGIN
    -- Add created_at column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'downloads' AND column_name = 'created_at'
    ) THEN
        ALTER TABLE downloads ADD COLUMN created_at TIMESTAMP WITH TIME ZONE DEFAULT now();
    END IF;
END $$;

-- ========== SHARES TABLE (File Sharing) ==========
CREATE TABLE IF NOT EXISTS shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    shared_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    shared_with UUID REFERENCES users(id) ON DELETE CASCADE, -- NULL = public share
    share_token VARCHAR(255) UNIQUE, -- For anonymous/link sharing
    permission_level VARCHAR(50) NOT NULL DEFAULT 'read', -- read, write, admin
    expires_at TIMESTAMP WITH TIME ZONE,
    max_downloads INTEGER, -- NULL = unlimited
    download_count INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    accessed_at TIMESTAMP WITH TIME ZONE -- Last access time
);

-- ========== QUOTA TRACKING TABLE ==========
CREATE TABLE IF NOT EXISTS quota_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL, -- UPLOAD, DELETE, etc.
    file_id UUID REFERENCES files(id) ON DELETE SET NULL,
    size_delta BIGINT NOT NULL, -- positive for uploads, negative for deletes
    quota_before BIGINT NOT NULL,
    quota_after BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- ========== AUDIT LOGS ==========
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL, -- FILE_UPLOAD, FILE_DELETE, SHARE_CREATE, etc.
    resource_type VARCHAR(50) NOT NULL, -- FILE, FOLDER, SHARE, USER
    resource_id UUID,
    metadata JSONB, -- Additional context data
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- ========== UPLOAD REQUESTS TABLE ==========
-- Table to track upload requests
CREATE TABLE IF NOT EXISTS upload_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(255) NOT NULL,
    folder_id UUID REFERENCES folders(id) ON DELETE SET NULL,
    s3_key TEXT NOT NULL,
    upload_url TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- PENDING, COMPLETED, EXPIRED, FAILED
    description TEXT,
    tags TEXT[],
    is_public BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Update existing users to 100MB quota
UPDATE users SET quota_limit = 104857600 WHERE quota_limit = 10485760;

-- ========== INDEXES (Create only if they don't exist and columns exist) ==========
-- Users
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- Blobs - Only create indexes if columns exist
DO $$
BEGIN
    -- Check if all required columns exist before creating indexes
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'blobs' AND column_name = 's3_key') THEN
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_blobs_s3_key') THEN
            CREATE INDEX idx_blobs_s3_key ON blobs(s3_key);
        END IF;
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'blobs' AND column_name = 'upload_status') THEN
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_blobs_status') THEN
            CREATE INDEX idx_blobs_status ON blobs(upload_status);
        END IF;
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'blobs' AND column_name = 'mime_type') THEN
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_blobs_mime') THEN
            CREATE INDEX idx_blobs_mime ON blobs(mime_type);
        END IF;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_blobs_content_hash ON blobs(content_hash);
CREATE INDEX IF NOT EXISTS idx_blobs_size ON blobs(size_bytes);
CREATE INDEX IF NOT EXISTS idx_blobs_deleted_at ON blobs(deleted_at);

-- Folders
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_folder_id);
CREATE INDEX IF NOT EXISTS idx_folders_owner ON folders(owner_id);
CREATE INDEX IF NOT EXISTS idx_folders_name ON folders(name);

-- Files - Only create indexes if columns exist
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'files' AND column_name = 'blob_id') THEN
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_files_blob') THEN
            CREATE INDEX idx_files_blob ON files(blob_id);
        END IF;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
CREATE INDEX IF NOT EXISTS idx_files_public ON files(is_public);
CREATE INDEX IF NOT EXISTS idx_files_deleted ON files(deleted_at);
CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at);
CREATE INDEX IF NOT EXISTS idx_files_download_count ON files(download_count);

-- GIN indexes for full-text search (create only if they don't exist)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_files_filename'
    ) THEN
        CREATE INDEX idx_files_filename ON files USING gin(to_tsvector('english', filename));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_files_tags'
    ) THEN
        CREATE INDEX idx_files_tags ON files USING gin(tags);
    END IF;
END $$;

-- Downloads - Only create indexes if columns exist
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'downloads' AND column_name = 'created_at') THEN
        IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_downloads_date') THEN
            CREATE INDEX idx_downloads_date ON downloads(created_at);
        END IF;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_downloads_file ON downloads(file_id);
CREATE INDEX IF NOT EXISTS idx_downloads_user ON downloads(downloaded_by);
CREATE INDEX IF NOT EXISTS idx_downloads_status ON downloads(status);

-- Shares
CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id);
CREATE INDEX IF NOT EXISTS idx_shares_token ON shares(share_token);
CREATE INDEX IF NOT EXISTS idx_shares_shared_by ON shares(shared_by);
CREATE INDEX IF NOT EXISTS idx_shares_shared_with ON shares(shared_with);
CREATE INDEX IF NOT EXISTS idx_shares_active ON shares(is_active);
CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares(expires_at);

-- Quota logs
CREATE INDEX IF NOT EXISTS idx_quota_logs_user ON quota_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_quota_logs_action ON quota_logs(action);
CREATE INDEX IF NOT EXISTS idx_quota_logs_created ON quota_logs(created_at);

-- Audit logs
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_date ON audit_logs(created_at);

-- Upload requests
CREATE INDEX IF NOT EXISTS idx_upload_requests_user ON upload_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_upload_requests_status ON upload_requests(status);
CREATE INDEX IF NOT EXISTS idx_upload_requests_expires ON upload_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_upload_requests_s3_key ON upload_requests(s3_key);

-- ========== FUNCTIONS & TRIGGERS ==========
-- Auto-update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers only if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger 
        WHERE tgname = 'update_users_updated_at'
    ) THEN
        CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger 
        WHERE tgname = 'update_folders_updated_at'
    ) THEN
        CREATE TRIGGER update_folders_updated_at BEFORE UPDATE ON folders 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger 
        WHERE tgname = 'update_files_updated_at'
    ) THEN
        CREATE TRIGGER update_files_updated_at BEFORE UPDATE ON files 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

-- ========== FILE SHARES TABLE (Share Links) ==========
CREATE TABLE IF NOT EXISTS file_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Add indexes for file_shares table
CREATE INDEX IF NOT EXISTS idx_file_shares_token ON file_shares(share_token);
CREATE INDEX IF NOT EXISTS idx_file_shares_file_id ON file_shares(file_id);
CREATE INDEX IF NOT EXISTS idx_file_shares_owner_id ON file_shares(owner_id);
CREATE INDEX IF NOT EXISTS idx_file_shares_active ON file_shares(is_active) WHERE is_active = true;

-- Add trigger for file_shares updated_at
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger 
        WHERE tgname = 'update_file_shares_updated_at'
    ) THEN
        CREATE TRIGGER update_file_shares_updated_at BEFORE UPDATE ON file_shares 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

-- Insert sample data only if users don't exist
INSERT INTO users (id, name, email, password_hash, role, quota_limit) 
SELECT '00000000-0000-0000-0000-000000000001', 'Admin User', 'admin@example.com', 
       '$2a$14$example.admin.hash', 'ADMIN', 1073741824
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@example.com');

INSERT INTO users (id, name, email, password_hash, role, quota_limit) 
SELECT '00000000-0000-0000-0000-000000000002', 'Test User', 'user@example.com', 
       '$2a$14$example.user.hash', 'USER', 10485760
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'user@example.com');