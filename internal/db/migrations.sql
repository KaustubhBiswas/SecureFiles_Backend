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

-- ========== FOLDER SHARING ENHANCEMENTS ==========
-- Add columns for public sharing and folder management
DO $$
BEGIN
    -- Add is_public column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'folders' AND column_name = 'is_public'
    ) THEN
        ALTER TABLE folders ADD COLUMN is_public BOOLEAN NOT NULL DEFAULT false;
        RAISE NOTICE 'Added is_public column to folders table';
    END IF;
    
    -- Add share_token for public links
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'folders' AND column_name = 'share_token'
    ) THEN
        ALTER TABLE folders ADD COLUMN share_token VARCHAR(255) UNIQUE;
        RAISE NOTICE 'Added share_token column to folders table';
    END IF;
    
    -- Add description
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'folders' AND column_name = 'description'
    ) THEN
        ALTER TABLE folders ADD COLUMN description TEXT;
        RAISE NOTICE 'Added description column to folders table';
    END IF;
    
    -- Add deleted_at for soft delete
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'folders' AND column_name = 'deleted_at'
    ) THEN
        ALTER TABLE folders ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE;
        RAISE NOTICE 'Added deleted_at column to folders table';
    END IF;
    
    -- Add color for UI customization
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'folders' AND column_name = 'color'
    ) THEN
        ALTER TABLE folders ADD COLUMN color VARCHAR(20);
        RAISE NOTICE 'Added color column to folders table';
    END IF;
    
    -- Add inherit_public flag to control cascading
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'folders' AND column_name = 'inherit_public'
    ) THEN
        ALTER TABLE folders ADD COLUMN inherit_public BOOLEAN NOT NULL DEFAULT true;
        RAISE NOTICE 'Added inherit_public column to folders table';
    END IF;
END $$;

-- Create folder_permissions table for granular access control
CREATE TABLE IF NOT EXISTS folder_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_level VARCHAR(20) NOT NULL DEFAULT 'READ', -- READ, WRITE, ADMIN
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    granted_by UUID REFERENCES users(id),
    UNIQUE(folder_id, user_id)
);

-- Create folder_access_logs table for audit trail
CREATE TABLE IF NOT EXISTS folder_access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    access_type VARCHAR(50) NOT NULL, -- view, download, share_link
    ip_address VARCHAR(45),
    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create folder_paths materialized view for efficient breadcrumb queries
CREATE TABLE IF NOT EXISTS folder_paths (
    folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    ancestor_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    depth INTEGER NOT NULL,
    PRIMARY KEY (folder_id, ancestor_id)
);

-- ========== FOLDER INDEXES ==========
DO $$
BEGIN
    -- Index for share token lookups
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folders_share_token'
    ) THEN
        CREATE INDEX idx_folders_share_token ON folders(share_token) WHERE share_token IS NOT NULL;
    END IF;
    
    -- Index for public folders
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folders_is_public'
    ) THEN
        CREATE INDEX idx_folders_is_public ON folders(is_public) WHERE is_public = true;
    END IF;
    
    -- Index for soft delete queries
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folders_deleted_at'
    ) THEN
        CREATE INDEX idx_folders_deleted_at ON folders(deleted_at) WHERE deleted_at IS NULL;
    END IF;
    
    -- Composite index for folder listing
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folders_owner_parent'
    ) THEN
        CREATE INDEX idx_folders_owner_parent ON folders(owner_id, parent_folder_id);
    END IF;
    
    -- Index for permission lookups
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folder_permissions_folder'
    ) THEN
        CREATE INDEX idx_folder_permissions_folder ON folder_permissions(folder_id);
    END IF;
    
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folder_permissions_user'
    ) THEN
        CREATE INDEX idx_folder_permissions_user ON folder_permissions(user_id);
    END IF;
    
    -- Index for access logs
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folder_access_logs_folder'
    ) THEN
        CREATE INDEX idx_folder_access_logs_folder ON folder_access_logs(folder_id);
    END IF;
    
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folder_access_logs_accessed_at'
    ) THEN
        CREATE INDEX idx_folder_access_logs_accessed_at ON folder_access_logs(accessed_at DESC);
    END IF;
    
    -- Indexes for folder_paths
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folder_paths_folder'
    ) THEN
        CREATE INDEX idx_folder_paths_folder ON folder_paths(folder_id);
    END IF;
    
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_folder_paths_ancestor'
    ) THEN
        CREATE INDEX idx_folder_paths_ancestor ON folder_paths(ancestor_id);
    END IF;
END $$;

-- ========== FOLDER HELPER FUNCTIONS ==========

-- Function to check if folder is descendant of another
CREATE OR REPLACE FUNCTION is_folder_descendant(child_id UUID, parent_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM folder_paths 
        WHERE folder_id = child_id AND ancestor_id = parent_id
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to get folder breadcrumb path
CREATE OR REPLACE FUNCTION get_folder_breadcrumb(folder_id_param UUID)
RETURNS TABLE (
    id UUID,
    name VARCHAR,
    parent_folder_id UUID,
    depth INTEGER
) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE breadcrumb AS (
        SELECT f.id, f.name, f.parent_folder_id, 0 as depth
        FROM folders f
        WHERE f.id = folder_id_param AND f.deleted_at IS NULL
        
        UNION ALL
        
        SELECT f.id, f.name, f.parent_folder_id, b.depth + 1
        FROM folders f
        INNER JOIN breadcrumb b ON f.id = b.parent_folder_id
        WHERE f.deleted_at IS NULL
    )
    SELECT * FROM breadcrumb ORDER BY depth DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to rebuild folder_paths table
CREATE OR REPLACE FUNCTION rebuild_folder_paths()
RETURNS void AS $$
BEGIN
    TRUNCATE folder_paths;
    
    INSERT INTO folder_paths (folder_id, ancestor_id, depth)
    WITH RECURSIVE folder_tree AS (
        -- Base case: each folder is its own ancestor at depth 0
        SELECT id as folder_id, id as ancestor_id, 0 as depth
        FROM folders
        WHERE deleted_at IS NULL
        
        UNION ALL
        
        -- Recursive case: inherit ancestors from parent
        SELECT f.id, ft.ancestor_id, ft.depth + 1
        FROM folders f
        INNER JOIN folder_tree ft ON f.parent_folder_id = ft.folder_id
        WHERE f.deleted_at IS NULL
    )
    SELECT * FROM folder_tree;
END;
$$ LANGUAGE plpgsql;

-- Function to update folder paths when folder is moved or created
CREATE OR REPLACE FUNCTION update_folder_paths()
RETURNS TRIGGER AS $$
BEGIN
    -- Rebuild paths for the affected folder and its descendants
    IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND OLD.parent_folder_id IS DISTINCT FROM NEW.parent_folder_id) THEN
        -- Delete old paths for this folder and its descendants
        DELETE FROM folder_paths 
        WHERE folder_id IN (
            WITH RECURSIVE descendants AS (
                SELECT id FROM folders WHERE id = NEW.id
                UNION ALL
                SELECT f.id FROM folders f
                INNER JOIN descendants d ON f.parent_folder_id = d.id
            )
            SELECT id FROM descendants
        );
        
        -- Rebuild paths for this folder and its descendants
        INSERT INTO folder_paths (folder_id, ancestor_id, depth)
        WITH RECURSIVE folder_subtree AS (
            -- Get all ancestors of the new parent (or self if root)
            SELECT fp.folder_id, fp.ancestor_id, fp.depth
            FROM folder_paths fp
            WHERE fp.folder_id = COALESCE(NEW.parent_folder_id, NEW.id)
            
            UNION ALL
            
            -- Add the new folder itself at appropriate depth
            SELECT NEW.id, fp.ancestor_id, fp.depth + 1
            FROM folder_paths fp
            WHERE fp.folder_id = COALESCE(NEW.parent_folder_id, NEW.id)
            
            UNION
            
            -- Self-reference
            SELECT NEW.id, NEW.id, 0
        ),
        descendants AS (
            -- Get all descendants recursively
            SELECT id, parent_folder_id, 0 as relative_depth FROM folders WHERE id = NEW.id
            UNION ALL
            SELECT f.id, f.parent_folder_id, d.relative_depth + 1
            FROM folders f
            INNER JOIN descendants d ON f.parent_folder_id = d.id
        )
        SELECT d.id as folder_id, fs.ancestor_id, fs.depth + d.relative_depth as depth
        FROM descendants d
        CROSS JOIN folder_subtree fs
        ON CONFLICT (folder_id, ancestor_id) DO NOTHING;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for automatic path updates
DROP TRIGGER IF EXISTS trigger_update_folder_paths ON folders;
CREATE TRIGGER trigger_update_folder_paths
    AFTER INSERT OR UPDATE OF parent_folder_id ON folders
    FOR EACH ROW
    WHEN (NEW.deleted_at IS NULL)
    EXECUTE FUNCTION update_folder_paths();

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