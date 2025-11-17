-- =========================================
-- FOLDER SHARING FEATURE MIGRATION
-- =========================================
-- This migration adds public sharing capabilities to folders
-- Run this script to add folder sharing features to SecureFiles

-- ========== ADD COLUMNS TO FOLDERS TABLE ==========

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
    
    -- Add color for UI customization (optional)
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

-- ========== CREATE INDEXES FOR PERFORMANCE ==========

-- Create index on share_token for fast lookup
CREATE INDEX IF NOT EXISTS idx_folders_share_token 
ON folders(share_token) 
WHERE share_token IS NOT NULL;

-- Create index on parent_folder_id for hierarchy queries
CREATE INDEX IF NOT EXISTS idx_folders_parent_folder_id 
ON folders(parent_folder_id);

-- Create index on owner_id for user's folders
CREATE INDEX IF NOT EXISTS idx_folders_owner_id 
ON folders(owner_id);

-- Create index on deleted_at for soft delete filtering
CREATE INDEX IF NOT EXISTS idx_folders_deleted_at 
ON folders(deleted_at) 
WHERE deleted_at IS NOT NULL;

-- ========== FOLDER_PERMISSIONS TABLE ==========

CREATE TABLE IF NOT EXISTS folder_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,  -- NULL = public access
    permission_level VARCHAR(50) NOT NULL DEFAULT 'read', -- read, write, admin
    granted_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(folder_id, user_id)
);

-- Indexes for folder_permissions
CREATE INDEX IF NOT EXISTS idx_folder_permissions_folder_id 
ON folder_permissions(folder_id);

CREATE INDEX IF NOT EXISTS idx_folder_permissions_user_id 
ON folder_permissions(user_id);

CREATE INDEX IF NOT EXISTS idx_folder_permissions_expires_at 
ON folder_permissions(expires_at) 
WHERE expires_at IS NOT NULL;

-- ========== FOLDER_ACCESS_LOGS TABLE ==========

CREATE TABLE IF NOT EXISTS folder_access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,  -- NULL = anonymous
    ip_address INET,
    user_agent TEXT,
    accessed_via VARCHAR(50),  -- 'share_link', 'direct', 'search'
    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Indexes for folder_access_logs
CREATE INDEX IF NOT EXISTS idx_folder_access_logs_folder_id 
ON folder_access_logs(folder_id);

CREATE INDEX IF NOT EXISTS idx_folder_access_logs_accessed_at 
ON folder_access_logs(accessed_at);

CREATE INDEX IF NOT EXISTS idx_folder_access_logs_user_id 
ON folder_access_logs(user_id);

-- ========== FOLDER_PATHS TABLE (Materialized Path for Performance) ==========

CREATE TABLE IF NOT EXISTS folder_paths (
    ancestor_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    descendant_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    depth INT NOT NULL DEFAULT 0,
    PRIMARY KEY (ancestor_id, descendant_id)
);

-- Indexes for folder_paths
CREATE INDEX IF NOT EXISTS idx_folder_paths_descendant 
ON folder_paths(descendant_id);

CREATE INDEX IF NOT EXISTS idx_folder_paths_depth 
ON folder_paths(depth);

-- ========== TRIGGER TO MAINTAIN FOLDER_PATHS ==========

-- Function to maintain folder_paths on folder insert
CREATE OR REPLACE FUNCTION maintain_folder_paths_insert()
RETURNS TRIGGER AS $$
BEGIN
    -- Add self-reference
    INSERT INTO folder_paths (ancestor_id, descendant_id, depth)
    VALUES (NEW.id, NEW.id, 0);
    
    -- Add paths from ancestors
    IF NEW.parent_folder_id IS NOT NULL THEN
        INSERT INTO folder_paths (ancestor_id, descendant_id, depth)
        SELECT ancestor_id, NEW.id, depth + 1
        FROM folder_paths
        WHERE descendant_id = NEW.parent_folder_id;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for insert
DROP TRIGGER IF EXISTS folder_paths_insert_trigger ON folders;
CREATE TRIGGER folder_paths_insert_trigger
AFTER INSERT ON folders
FOR EACH ROW
EXECUTE FUNCTION maintain_folder_paths_insert();

-- Function to maintain folder_paths on folder update (when parent changes)
CREATE OR REPLACE FUNCTION maintain_folder_paths_update()
RETURNS TRIGGER AS $$
BEGIN
    -- Only process if parent_folder_id changed
    IF OLD.parent_folder_id IS DISTINCT FROM NEW.parent_folder_id THEN
        -- Remove old paths (except self-reference)
        DELETE FROM folder_paths
        WHERE descendant_id IN (
            SELECT descendant_id FROM folder_paths WHERE ancestor_id = NEW.id
        )
        AND ancestor_id NOT IN (
            SELECT descendant_id FROM folder_paths WHERE ancestor_id = NEW.id
        );
        
        -- Re-add paths from new parent
        IF NEW.parent_folder_id IS NOT NULL THEN
            INSERT INTO folder_paths (ancestor_id, descendant_id, depth)
            SELECT fp.ancestor_id, fp_child.descendant_id, fp.depth + fp_child.depth + 1
            FROM folder_paths fp
            CROSS JOIN folder_paths fp_child
            WHERE fp.descendant_id = NEW.parent_folder_id
            AND fp_child.ancestor_id = NEW.id
            ON CONFLICT (ancestor_id, descendant_id) DO NOTHING;
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for update
DROP TRIGGER IF EXISTS folder_paths_update_trigger ON folders;
CREATE TRIGGER folder_paths_update_trigger
AFTER UPDATE ON folders
FOR EACH ROW
WHEN (OLD.parent_folder_id IS DISTINCT FROM NEW.parent_folder_id)
EXECUTE FUNCTION maintain_folder_paths_update();

-- ========== HELPER FUNCTIONS ==========

-- Function to get all descendant folders
CREATE OR REPLACE FUNCTION get_descendant_folders(folder_uuid UUID)
RETURNS TABLE(folder_id UUID, depth INT) AS $$
BEGIN
    RETURN QUERY
    SELECT descendant_id, folder_paths.depth
    FROM folder_paths
    WHERE ancestor_id = folder_uuid
    AND descendant_id != folder_uuid
    ORDER BY depth;
END;
$$ LANGUAGE plpgsql;

-- Function to get all ancestor folders (breadcrumb path)
CREATE OR REPLACE FUNCTION get_ancestor_folders(folder_uuid UUID)
RETURNS TABLE(folder_id UUID, depth INT) AS $$
BEGIN
    RETURN QUERY
    SELECT ancestor_id, folder_paths.depth
    FROM folder_paths
    WHERE descendant_id = folder_uuid
    AND ancestor_id != folder_uuid
    ORDER BY depth DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to check if user can access folder (considering inheritance)
CREATE OR REPLACE FUNCTION can_access_folder(folder_uuid UUID, user_uuid UUID)
RETURNS BOOLEAN AS $$
DECLARE
    is_owner BOOLEAN;
    is_public_accessible BOOLEAN;
BEGIN
    -- Check if user is owner
    SELECT EXISTS (
        SELECT 1 FROM folders 
        WHERE id = folder_uuid 
        AND owner_id = user_uuid 
        AND deleted_at IS NULL
    ) INTO is_owner;
    
    IF is_owner THEN
        RETURN TRUE;
    END IF;
    
    -- Check if folder or any ancestor is public
    SELECT EXISTS (
        SELECT 1 FROM folder_paths fp
        JOIN folders f ON f.id = fp.ancestor_id
        WHERE fp.descendant_id = folder_uuid
        AND f.is_public = TRUE
        AND f.deleted_at IS NULL
    ) INTO is_public_accessible;
    
    RETURN is_public_accessible;
END;
$$ LANGUAGE plpgsql;

-- Function to get folder statistics
CREATE OR REPLACE FUNCTION get_folder_stats(folder_uuid UUID)
RETURNS TABLE(
    total_files BIGINT,
    total_size BIGINT,
    total_subfolders BIGINT
) AS $$
BEGIN
    RETURN QUERY
    WITH descendant_folders AS (
        SELECT descendant_id FROM folder_paths WHERE ancestor_id = folder_uuid
    )
    SELECT 
        COUNT(DISTINCT f.id)::BIGINT as total_files,
        COALESCE(SUM(f.size), 0)::BIGINT as total_size,
        (SELECT COUNT(*)::BIGINT FROM descendant_folders WHERE descendant_id != folder_uuid) as total_subfolders
    FROM descendant_folders df
    LEFT JOIN files f ON f.folder_id = df.descendant_id AND f.deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql;

-- ========== POPULATE EXISTING FOLDER PATHS ==========

-- Populate folder_paths for existing folders
DO $$
DECLARE
    folder_record RECORD;
BEGIN
    -- Clear existing paths (in case of re-run)
    TRUNCATE folder_paths;
    
    -- Insert all folder paths using recursive CTE
    INSERT INTO folder_paths (ancestor_id, descendant_id, depth)
    WITH RECURSIVE folder_hierarchy AS (
        -- Self-references (depth 0)
        SELECT id as ancestor_id, id as descendant_id, 0 as depth
        FROM folders
        WHERE deleted_at IS NULL
        
        UNION ALL
        
        -- Parent-child relationships
        SELECT fh.ancestor_id, f.id as descendant_id, fh.depth + 1
        FROM folder_hierarchy fh
        JOIN folders f ON f.parent_folder_id = fh.descendant_id
        WHERE f.deleted_at IS NULL
    )
    SELECT * FROM folder_hierarchy
    ON CONFLICT (ancestor_id, descendant_id) DO NOTHING;
    
    RAISE NOTICE 'Populated folder_paths table with existing folder hierarchy';
END $$;

-- ========== MIGRATION COMPLETE ==========

DO $$
BEGIN
    RAISE NOTICE '✅ Folder sharing migration completed successfully!';
    RAISE NOTICE 'Added columns: is_public, share_token, description, color, inherit_public, deleted_at';
    RAISE NOTICE 'Created tables: folder_permissions, folder_access_logs, folder_paths';
    RAISE NOTICE 'Created triggers: folder_paths_insert_trigger, folder_paths_update_trigger';
    RAISE NOTICE 'Created functions: get_descendant_folders, get_ancestor_folders, can_access_folder, get_folder_stats';
END $$;
