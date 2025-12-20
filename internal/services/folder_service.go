package services

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type FolderService struct {
	db *sql.DB
}

func NewFolderService(db *sql.DB) *FolderService {
	return &FolderService{db: db}
}

// GenerateShareToken creates a unique share token
func (s *FolderService) GenerateShareToken() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetFolderByID retrieves folder with permission check
func (s *FolderService) GetFolderByID(ctx context.Context, folderID uuid.UUID, userID *uuid.UUID) (*Folder, error) {
	query := `
		SELECT id, name, parent_folder_id, owner_id, is_public, share_token, 
		       description, color, inherit_public, created_at, updated_at
		FROM folders
		WHERE id = $1 AND deleted_at IS NULL
	`

	folder := &Folder{}
	err := s.db.QueryRowContext(ctx, query, folderID).Scan(
		&folder.ID, &folder.Name, &folder.ParentID, &folder.OwnerID,
		&folder.IsPublic, &folder.ShareToken, &folder.Description,
		&folder.Color, &folder.InheritPublic, &folder.CreatedAt, &folder.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Check access permission
	if !s.CanAccessFolder(ctx, folderID, userID) {
		return nil, fmt.Errorf("access denied")
	}

	return folder, nil
}

// CanAccessFolder checks if user can access folder (considering inheritance)
func (s *FolderService) CanAccessFolder(ctx context.Context, folderID uuid.UUID, userID *uuid.UUID) bool {
	// If user is owner, always allow
	if userID != nil {
		var ownerID uuid.UUID
		err := s.db.QueryRowContext(ctx, "SELECT owner_id FROM folders WHERE id = $1", folderID).Scan(&ownerID)
		if err == nil && ownerID == *userID {
			return true
		}
	}

	// Check if folder is public or inherits public status
	query := `
		WITH RECURSIVE folder_hierarchy AS (
			-- Start with the requested folder
			SELECT id, parent_folder_id, is_public, inherit_public, owner_id
			FROM folders
			WHERE id = $1 AND deleted_at IS NULL
			
			UNION ALL
			
			-- Recursively get parent folders
			SELECT f.id, f.parent_folder_id, f.is_public, f.inherit_public, f.owner_id
			FROM folders f
			INNER JOIN folder_hierarchy fh ON f.id = fh.parent_folder_id
			WHERE f.deleted_at IS NULL
		)
		SELECT EXISTS (
			SELECT 1 FROM folder_hierarchy
			WHERE is_public = true
			LIMIT 1
		)
	`

	var isAccessible bool
	err := s.db.QueryRowContext(ctx, query, folderID).Scan(&isAccessible)
	return err == nil && isAccessible
}

// GetFolderPath returns breadcrumb path from root to folder
func (s *FolderService) GetFolderPath(ctx context.Context, folderID uuid.UUID) ([]Folder, error) {
	query := `
		WITH RECURSIVE folder_path AS (
			SELECT id, name, parent_folder_id, 0 as depth
			FROM folders
			WHERE id = $1 AND deleted_at IS NULL
			
			UNION ALL
			
			SELECT f.id, f.name, f.parent_folder_id, fp.depth + 1
			FROM folders f
			INNER JOIN folder_path fp ON f.id = fp.parent_folder_id
			WHERE f.deleted_at IS NULL
		)
		SELECT id, name
		FROM folder_path
		ORDER BY depth DESC
	`

	rows, err := s.db.QueryContext(ctx, query, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var path []Folder
	for rows.Next() {
		var folder Folder
		if err := rows.Scan(&folder.ID, &folder.Name); err != nil {
			return nil, err
		}
		path = append(path, folder)
	}

	return path, nil
}

// GetFolderContents retrieves immediate children folders and files
func (s *FolderService) GetFolderContents(ctx context.Context, folderID *uuid.UUID, userID uuid.UUID) ([]Folder, []File, error) {
	// Get child folders - filter by owner and parent folder
	var foldersQuery string
	var args []interface{}

	if folderID == nil {
		// Root folder - get folders with no parent for this user
		foldersQuery = `
			SELECT id, name, parent_folder_id, owner_id, is_public, share_token,
			       description, color, inherit_public, created_at, updated_at
			FROM folders
			WHERE parent_folder_id IS NULL 
			  AND owner_id = $1
			  AND deleted_at IS NULL
			ORDER BY name ASC
		`
		args = []interface{}{userID}
	} else {
		// Child folder - get folders with this parent for this user
		foldersQuery = `
			SELECT id, name, parent_folder_id, owner_id, is_public, share_token,
			       description, color, inherit_public, created_at, updated_at
			FROM folders
			WHERE parent_folder_id = $1 
			  AND owner_id = $2
			  AND deleted_at IS NULL
			ORDER BY name ASC
		`
		args = []interface{}{*folderID, userID}
	}

	folderRows, err := s.db.QueryContext(ctx, foldersQuery, args...)
	if err != nil {
		return nil, nil, err
	}
	defer folderRows.Close()

	var folders []Folder
	for folderRows.Next() {
		var folder Folder
		if err := folderRows.Scan(
			&folder.ID, &folder.Name, &folder.ParentID, &folder.OwnerID,
			&folder.IsPublic, &folder.ShareToken, &folder.Description,
			&folder.Color, &folder.InheritPublic, &folder.CreatedAt, &folder.UpdatedAt,
		); err != nil {
			return nil, nil, err
		}
		folders = append(folders, folder)
	}

	// Get files - temporarily return empty array
	var files []File

	return folders, files, nil
}

// GenerateFolderShareLink creates or returns existing share link
func (s *FolderService) GenerateFolderShareLink(ctx context.Context, folderID uuid.UUID, userID uuid.UUID) (string, error) {
	// Check ownership
	var ownerID uuid.UUID
	err := s.db.QueryRowContext(ctx, "SELECT owner_id FROM folders WHERE id = $1", folderID).Scan(&ownerID)
	if err != nil {
		return "", err
	}
	if ownerID != userID {
		return "", fmt.Errorf("only owner can share folder")
	}

	// Check if share token exists
	var existingToken sql.NullString
	err = s.db.QueryRowContext(ctx, "SELECT share_token FROM folders WHERE id = $1", folderID).Scan(&existingToken)
	if err != nil {
		return "", err
	}

	if existingToken.Valid && existingToken.String != "" {
		return existingToken.String, nil
	}

	// Generate new token
	token, err := s.GenerateShareToken()
	if err != nil {
		return "", err
	}

	// Update folder
	_, err = s.db.ExecContext(ctx, `
		UPDATE folders 
		SET share_token = $1, is_public = true, updated_at = $2
		WHERE id = $3
	`, token, time.Now(), folderID)

	if err != nil {
		return "", err
	}

	return token, nil
}

// RevokeFolderShareLink removes share link
func (s *FolderService) RevokeFolderShareLink(ctx context.Context, folderID uuid.UUID, userID uuid.UUID) error {
	// Check ownership
	var ownerID uuid.UUID
	err := s.db.QueryRowContext(ctx, "SELECT owner_id FROM folders WHERE id = $1", folderID).Scan(&ownerID)
	if err != nil {
		return err
	}
	if ownerID != userID {
		return fmt.Errorf("only owner can revoke share link")
	}

	_, err = s.db.ExecContext(ctx, `
		UPDATE folders 
		SET share_token = NULL, is_public = false, updated_at = $1
		WHERE id = $2
	`, time.Now(), folderID)

	return err
}

// LogFolderAccess records access to folder
func (s *FolderService) LogFolderAccess(ctx context.Context, folderID uuid.UUID, userID *uuid.UUID, ipAddress, accessedVia string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO folder_access_logs (folder_id, user_id, ip_address, accessed_via, accessed_at)
		VALUES ($1, $2, $3, $4, $5)
	`, folderID, userID, ipAddress, accessedVia, time.Now())

	return err
}

// GetFolderStats calculates statistics for a folder
func (s *FolderService) GetFolderStats(ctx context.Context, folderID uuid.UUID) (*FolderStats, error) {
	// Get total files and size recursively
	query := `
		WITH RECURSIVE folder_tree AS (
			SELECT id FROM folders WHERE id = $1 AND deleted_at IS NULL
			UNION ALL
			SELECT f.id FROM folders f
			INNER JOIN folder_tree ft ON f.parent_folder_id = ft.id
			WHERE f.deleted_at IS NULL
		)
		SELECT 
			COUNT(DISTINCT files.id)::BIGINT as total_files,
			COALESCE(SUM(files.file_size), 0)::BIGINT as total_size
		FROM folder_tree
		LEFT JOIN files ON files.folder_id = folder_tree.id AND files.deleted_at IS NULL
	`

	stats := &FolderStats{}

	err := s.db.QueryRowContext(ctx, query, folderID).Scan(
		&stats.TotalFiles,
		&stats.TotalSize,
	)

	if err != nil {
		return nil, err
	}

	return stats, nil
}

// GetFolderByShareToken retrieves a folder by its share token for public access
func (s *FolderService) GetFolderByShareToken(ctx context.Context, shareToken string) (*Folder, error) {
	query := `
		SELECT id, name, parent_folder_id, owner_id, is_public, share_token, 
		       description, color, inherit_public, created_at, updated_at
		FROM folders
		WHERE share_token = $1 AND deleted_at IS NULL AND is_public = true
	`

	folder := &Folder{}
	err := s.db.QueryRowContext(ctx, query, shareToken).Scan(
		&folder.ID, &folder.Name, &folder.ParentID, &folder.OwnerID,
		&folder.IsPublic, &folder.ShareToken, &folder.Description,
		&folder.Color, &folder.InheritPublic, &folder.CreatedAt, &folder.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return folder, nil
}

// GetPublicFolderContents retrieves subfolders and files for public folder access
func (s *FolderService) GetPublicFolderContents(ctx context.Context, folderID uuid.UUID, subPath *string) ([]Folder, []File, error) {
	// Navigate to subpath if provided
	targetFolderID := folderID
	if subPath != nil && *subPath != "" && *subPath != "/" {
		// Parse path and navigate
		pathParts := strings.Split(strings.Trim(*subPath, "/"), "/")
		currentID := folderID

		for _, part := range pathParts {
			if part == "" {
				continue
			}

			var nextID uuid.UUID
			err := s.db.QueryRowContext(ctx, `
				SELECT id FROM folders 
				WHERE parent_folder_id = $1 AND name = $2 AND deleted_at IS NULL
			`, currentID, part).Scan(&nextID)

			if err != nil {
				return nil, nil, fmt.Errorf("path not found: %s", *subPath)
			}
			currentID = nextID
		}
		targetFolderID = currentID
	}

	// Get child folders
	foldersQuery := `
		SELECT id, name, parent_folder_id, owner_id, is_public, share_token,
		       description, color, inherit_public, created_at, updated_at
		FROM folders
		WHERE parent_folder_id = $1 AND deleted_at IS NULL AND (is_public = true OR inherit_public = true)
		ORDER BY name ASC
	`

	folderRows, err := s.db.QueryContext(ctx, foldersQuery, targetFolderID)
	if err != nil {
		return nil, nil, err
	}
	defer folderRows.Close()

	var folders []Folder
	for folderRows.Next() {
		var folder Folder
		if err := folderRows.Scan(
			&folder.ID, &folder.Name, &folder.ParentID, &folder.OwnerID,
			&folder.IsPublic, &folder.ShareToken, &folder.Description,
			&folder.Color, &folder.InheritPublic, &folder.CreatedAt, &folder.UpdatedAt,
		); err != nil {
			return nil, nil, err
		}
		folders = append(folders, folder)
	}

	// Get files in folder
	filesQuery := `
		SELECT id, filename, original_filename, file_size, 
		       COALESCE((SELECT mime_type FROM blobs WHERE id = files.blob_id), 'application/octet-stream') as mime_type,
		       is_public, description, folder_id, download_count, created_at, updated_at
		FROM files
		WHERE folder_id = $1 AND deleted_at IS NULL
		ORDER BY original_filename ASC
	`

	fileRows, err := s.db.QueryContext(ctx, filesQuery, targetFolderID)
	if err != nil {
		return nil, nil, err
	}
	defer fileRows.Close()

	var files []File
	for fileRows.Next() {
		var file File
		if err := fileRows.Scan(
			&file.ID, &file.Filename, &file.OriginalFilename, &file.Size,
			&file.MimeType, &file.IsPublic, &file.Description, &file.FolderId,
			&file.DownloadCount, &file.CreatedAt, &file.UpdatedAt,
		); err != nil {
			return nil, nil, err
		}
		files = append(files, file)
	}

	return folders, files, nil
}

// CreateFolder creates a new folder
func (s *FolderService) CreateFolder(ctx context.Context, name string, parentID *uuid.UUID, ownerID uuid.UUID, description, color *string) (*Folder, error) {
	// Validate parent exists and user has access
	if parentID != nil {
		if !s.CanAccessFolder(ctx, *parentID, &ownerID) {
			return nil, fmt.Errorf("cannot create folder in inaccessible parent")
		}
	}

	folderID := uuid.New()
	now := time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO folders (id, name, parent_folder_id, owner_id, description, color, is_public, inherit_public, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, false, true, $7, $8)
	`, folderID, name, parentID, ownerID, description, color, now, now)

	if err != nil {
		return nil, err
	}

	return s.GetFolderByID(ctx, folderID, &ownerID)
}

// UpdateFolder updates folder properties
func (s *FolderService) UpdateFolder(ctx context.Context, folderID uuid.UUID, userID uuid.UUID, input UpdateFolderInput) (*Folder, error) {
	// Check ownership
	var ownerID uuid.UUID
	err := s.db.QueryRowContext(ctx, "SELECT owner_id FROM folders WHERE id = $1", folderID).Scan(&ownerID)
	if err != nil {
		return nil, err
	}
	if ownerID != userID {
		return nil, fmt.Errorf("only owner can update folder")
	}

	// Build dynamic update query
	query := "UPDATE folders SET updated_at = $1"
	args := []interface{}{time.Now()}
	argCount := 2

	if input.Name != nil {
		query += fmt.Sprintf(", name = $%d", argCount)
		args = append(args, *input.Name)
		argCount++
	}
	if input.Description != nil {
		query += fmt.Sprintf(", description = $%d", argCount)
		args = append(args, *input.Description)
		argCount++
	}
	if input.Color != nil {
		query += fmt.Sprintf(", color = $%d", argCount)
		args = append(args, *input.Color)
		argCount++
	}
	if input.IsPublic != nil {
		query += fmt.Sprintf(", is_public = $%d", argCount)
		args = append(args, *input.IsPublic)
		argCount++
	}
	if input.InheritPublic != nil {
		query += fmt.Sprintf(", inherit_public = $%d", argCount)
		args = append(args, *input.InheritPublic)
		argCount++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argCount)
	args = append(args, folderID)

	_, err = s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	return s.GetFolderByID(ctx, folderID, &userID)
}

// DeleteFolder soft deletes a folder and all its contents
func (s *FolderService) DeleteFolder(ctx context.Context, folderID uuid.UUID, userID uuid.UUID) error {
	// Check ownership
	var ownerID uuid.UUID
	err := s.db.QueryRowContext(ctx, "SELECT owner_id FROM folders WHERE id = $1", folderID).Scan(&ownerID)
	if err != nil {
		return err
	}
	if ownerID != userID {
		return fmt.Errorf("only owner can delete folder")
	}

	// Soft delete recursively
	now := time.Now()

	// Delete all descendant folders
	_, err = s.db.ExecContext(ctx, `
		WITH RECURSIVE folder_tree AS (
			SELECT id FROM folders WHERE id = $1
			UNION ALL
			SELECT f.id FROM folders f
			INNER JOIN folder_tree ft ON f.parent_folder_id = ft.id
		)
		UPDATE folders
		SET deleted_at = $2
		WHERE id IN (SELECT id FROM folder_tree)
	`, folderID, now)

	if err != nil {
		return err
	}

	// Delete all files in those folders
	_, err = s.db.ExecContext(ctx, `
		WITH RECURSIVE folder_tree AS (
			SELECT id FROM folders WHERE id = $1
			UNION ALL
			SELECT f.id FROM folders f
			INNER JOIN folder_tree ft ON f.parent_folder_id = ft.id
		)
		UPDATE files
		SET deleted_at = $2
		WHERE folder_id IN (SELECT id FROM folder_tree)
	`, folderID, now)

	return err
}

// MoveFolder moves folder to new parent
func (s *FolderService) MoveFolder(ctx context.Context, folderID uuid.UUID, newParentID *uuid.UUID, userID uuid.UUID) (*Folder, error) {
	// Check ownership
	var ownerID uuid.UUID
	err := s.db.QueryRowContext(ctx, "SELECT owner_id FROM folders WHERE id = $1", folderID).Scan(&ownerID)
	if err != nil {
		return nil, err
	}
	if ownerID != userID {
		return nil, fmt.Errorf("only owner can move folder")
	}

	// Validate new parent
	if newParentID != nil {
		// Check access to new parent
		if !s.CanAccessFolder(ctx, *newParentID, &userID) {
			return nil, fmt.Errorf("cannot move to inaccessible parent")
		}

		// Prevent circular reference
		if s.isDescendant(ctx, *newParentID, folderID) {
			return nil, fmt.Errorf("cannot move folder into its own descendant")
		}
	}

	_, err = s.db.ExecContext(ctx, `
		UPDATE folders 
		SET parent_folder_id = $1, updated_at = $2
		WHERE id = $3
	`, newParentID, time.Now(), folderID)

	if err != nil {
		return nil, err
	}

	return s.GetFolderByID(ctx, folderID, &userID)
}

// isDescendant checks if potentialDescendant is a descendant of ancestorID
func (s *FolderService) isDescendant(ctx context.Context, potentialDescendant, ancestorID uuid.UUID) bool {
	query := `
		WITH RECURSIVE folder_tree AS (
			SELECT id, parent_folder_id FROM folders WHERE id = $1
			UNION ALL
			SELECT f.id, f.parent_folder_id FROM folders f
			INNER JOIN folder_tree ft ON f.parent_folder_id = ft.id
		)
		SELECT EXISTS (SELECT 1 FROM folder_tree WHERE id = $2)
	`

	var exists bool
	err := s.db.QueryRowContext(ctx, query, ancestorID, potentialDescendant).Scan(&exists)
	return err == nil && exists
}

// Supporting types
type Folder struct {
	ID            uuid.UUID
	Name          string
	ParentID      *uuid.UUID
	OwnerID       uuid.UUID
	IsPublic      bool
	ShareToken    *string
	Description   *string
	Color         *string
	InheritPublic bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type File struct {
	ID               uuid.UUID
	Filename         string
	OriginalFilename string
	Size             int64
	MimeType         string
	IsPublic         bool
	Description      *string
	FolderId         *uuid.UUID
	DownloadCount    int
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type FolderStats struct {
	TotalFiles int64
	TotalSize  int64
}

type UpdateFolderInput struct {
	Name          *string
	Description   *string
	Color         *string
	IsPublic      *bool
	InheritPublic *bool
}
