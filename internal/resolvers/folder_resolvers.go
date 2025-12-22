package resolvers

import (
	"context"
	"fmt"
	"time"

	"backend/graph/model"
	"backend/internal/auth"
	"backend/internal/services"

	"github.com/google/uuid"
)

// Query Resolvers

func (r *queryResolver) Folder(ctx context.Context, id string) (*model.Folder, error) {
	folderID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid folder ID")
	}

	userIDStr := auth.GetUserIDFromContext(ctx)
	var userID *uuid.UUID
	if userIDStr != "" {
		parsed, err := uuid.Parse(userIDStr)
		if err != nil {
			return nil, fmt.Errorf("invalid user ID")
		}
		userID = &parsed
	}

	folder, err := r.FolderService.GetFolderByID(ctx, folderID, userID)
	if err != nil {
		return nil, err
	}

	return toGraphQLFolder(folder), nil
}

func (r *queryResolver) Folders(ctx context.Context, parentID *string) ([]*model.Folder, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	var parentUUID *uuid.UUID
	if parentID != nil {
		parsed, err := uuid.Parse(*parentID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent ID")
		}
		parentUUID = &parsed
	}

	folders, _, err := r.FolderService.GetFolderContents(ctx, parentUUID, userID)
	if err != nil {
		return nil, err
	}

	return toGraphQLFolders(folders), nil
}

func (r *queryResolver) FolderByPath(ctx context.Context, path string) (*model.Folder, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	_, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// For now, return an error - this needs proper implementation
	return nil, fmt.Errorf("FolderByPath not yet implemented")
}

// Mutation Resolvers

func (r *mutationResolver) CreateFolder(ctx context.Context, name string, parentID *string, color *string, description *string) (*model.Folder, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	var parentUUID *uuid.UUID
	if parentID != nil {
		parsed, err := uuid.Parse(*parentID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent ID")
		}
		parentUUID = &parsed
	}

	folder, err := r.FolderService.CreateFolder(ctx, name, parentUUID, userID, description, color)
	if err != nil {
		return nil, err
	}

	return toGraphQLFolder(folder), nil
}

func (r *mutationResolver) GenerateFolderShareLink(ctx context.Context, folderID string, expiresIn *int) (*model.ShareLinkResponse, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	parsedFolderID, err := uuid.Parse(folderID)
	if err != nil {
		return nil, fmt.Errorf("invalid folder ID")
	}

	token, err := r.FolderService.GenerateFolderShareLink(ctx, parsedFolderID, userID)
	if err != nil {
		return nil, err
	}

	// Build share URL
	shareURL := fmt.Sprintf("%s/public/folder/%s", r.FrontendURL, token)

	return &model.ShareLinkResponse{
		ShareToken: token,
		ShareURL:   shareURL,
		ExpiresAt:  nil,
		IsActive:   true,
	}, nil
}

func (r *mutationResolver) RevokeFolderShareLink(ctx context.Context, folderID string) (*model.DeleteResponse, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	parsedFolderID, err := uuid.Parse(folderID)
	if err != nil {
		return nil, fmt.Errorf("invalid folder ID")
	}

	err = r.FolderService.RevokeFolderShareLink(ctx, parsedFolderID, userID)
	if err != nil {
		return nil, err
	}

	return &model.DeleteResponse{
		Success: true,
		Message: "Share link revoked successfully",
	}, nil
}

func (r *mutationResolver) ToggleFolderPublic(ctx context.Context, folderID string) (*model.Folder, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	parsedFolderID, err := uuid.Parse(folderID)
	if err != nil {
		return nil, fmt.Errorf("invalid folder ID")
	}

	// Get current state
	userIDPtr := &userID
	folder, err := r.FolderService.GetFolderByID(ctx, parsedFolderID, userIDPtr)
	if err != nil {
		return nil, err
	}

	// Toggle
	newIsPublic := !folder.IsPublic
	input := services.UpdateFolderInput{
		IsPublic: &newIsPublic,
	}

	updatedFolder, err := r.FolderService.UpdateFolder(ctx, parsedFolderID, userID, input)
	if err != nil {
		return nil, err
	}

	return toGraphQLFolder(updatedFolder), nil
}

func (r *mutationResolver) UpdateFolderPermissions(ctx context.Context, folderID string, inheritPublic bool) (*model.Folder, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	parsedFolderID, err := uuid.Parse(folderID)
	if err != nil {
		return nil, fmt.Errorf("invalid folder ID")
	}

	input := services.UpdateFolderInput{
		InheritPublic: &inheritPublic,
	}

	updatedFolder, err := r.FolderService.UpdateFolder(ctx, parsedFolderID, userID, input)
	if err != nil {
		return nil, err
	}

	return toGraphQLFolder(updatedFolder), nil
}

func (r *mutationResolver) UpdateFolder(ctx context.Context, id string, input model.UpdateFolderInput) (*model.Folder, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	folderID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid folder ID")
	}

	// Convert GraphQL input to service input
	serviceInput := services.UpdateFolderInput{
		Name:          input.Name,
		Description:   input.Description,
		Color:         input.Color,
		IsPublic:      input.IsPublic,
		InheritPublic: input.InheritPublic,
	}

	folder, err := r.FolderService.UpdateFolder(ctx, folderID, userID, serviceInput)
	if err != nil {
		return nil, err
	}

	return toGraphQLFolder(folder), nil
}

func (r *mutationResolver) DeleteFolder(ctx context.Context, id string) (*model.DeleteResponse, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	folderID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid folder ID")
	}

	err = r.FolderService.DeleteFolder(ctx, folderID, userID)
	if err != nil {
		return nil, err
	}

	return &model.DeleteResponse{
		Success: true,
		Message: "Folder deleted successfully",
	}, nil
}

func (r *mutationResolver) MoveFolder(ctx context.Context, id string, newParentID *string) (*model.Folder, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	folderID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid folder ID")
	}

	var newParentUUID *uuid.UUID
	if newParentID != nil {
		parsed, err := uuid.Parse(*newParentID)
		if err != nil {
			return nil, fmt.Errorf("invalid new parent ID")
		}
		newParentUUID = &parsed
	}

	folder, err := r.FolderService.MoveFolder(ctx, folderID, newParentUUID, userID)
	if err != nil {
		return nil, err
	}

	return toGraphQLFolder(folder), nil
}

func (r *mutationResolver) MoveFile(ctx context.Context, id string, newFolderID *string) (*model.File, error) {
	userIDStr := auth.GetUserIDFromContext(ctx)
	if userIDStr == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	fileID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid file ID")
	}

	var newFolderUUID *uuid.UUID
	if newFolderID != nil {
		parsed, err := uuid.Parse(*newFolderID)
		if err != nil {
			return nil, fmt.Errorf("invalid folder ID")
		}
		newFolderUUID = &parsed
	}

	// Update file's folder_id
	_, err = r.DB.ExecContext(ctx, `
		UPDATE files 
		SET folder_id = $1, updated_at = $2
		WHERE id = $3 AND owner_id = $4 AND deleted_at IS NULL
	`, newFolderUUID, time.Now(), fileID, userID)

	if err != nil {
		return nil, err
	}

	// Query and return updated file
	var file model.File
	err = r.DB.QueryRowContext(ctx, `
		SELECT id, filename, original_filename, size, mime_type, is_public, description, download_count, created_at, updated_at
		FROM files 
		WHERE id = $1 AND deleted_at IS NULL
	`, fileID).Scan(
		&file.ID, &file.Filename, &file.OriginalFilename, &file.Size,
		&file.MimeType, &file.IsPublic, &file.Description, &file.DownloadCount,
		&file.CreatedAt, &file.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	file.Tags = []string{} // Default empty tags
	return &file, nil
}

// Helper functions

func toGraphQLFolder(f *services.Folder) *model.Folder {
	folder := &model.Folder{
		ID:            f.ID.String(),
		Name:          f.Name,
		OwnerID:       f.OwnerID.String(),
		IsPublic:      f.IsPublic,
		InheritPublic: f.InheritPublic,
		CreatedAt:     f.CreatedAt,
		UpdatedAt:     f.UpdatedAt,
	}

	if f.ParentID != nil {
		parentID := f.ParentID.String()
		folder.ParentID = &parentID
	}

	if f.ShareToken != nil {
		folder.ShareToken = f.ShareToken
	}

	if f.Description != nil {
		folder.Description = f.Description
	}

	if f.Color != nil {
		folder.Color = f.Color
	}

	return folder
}

func toGraphQLFolders(folders []services.Folder) []*model.Folder {
	result := make([]*model.Folder, len(folders))
	for i, f := range folders {
		result[i] = toGraphQLFolder(&f)
	}
	return result
}

func toGraphQLFiles(files []services.File) []*model.File {
	result := make([]*model.File, len(files))
	for i, f := range files {
		result[i] = toGraphQLFile(&f)
	}
	return result
}

func toGraphQLFile(f *services.File) *model.File {
	file := &model.File{
		ID:               f.ID.String(),
		Filename:         f.Filename,
		OriginalFilename: f.OriginalFilename,
		Size:             int(f.Size),
		MimeType:         f.MimeType,
		IsPublic:         f.IsPublic,
		DownloadCount:    f.DownloadCount,
		CreatedAt:        f.CreatedAt,
		UpdatedAt:        f.UpdatedAt,
		Tags:             []string{},
	}

	if f.Description != nil {
		file.Description = f.Description
	}

	if f.FolderId != nil {
		folderIdStr := f.FolderId.String()
		file.FolderID = &folderIdStr
	}

	return file
}

// Public Folder Resolvers

func (r *queryResolver) PublicFolder(ctx context.Context, shareToken string) (*model.PublicFolderView, error) {
	// Get folder by share token
	folder, err := r.FolderService.GetFolderByShareToken(ctx, shareToken)
	if err != nil {
		return nil, fmt.Errorf("folder not found or not public")
	}

	// Get folder stats
	stats, err := r.FolderService.GetFolderStats(ctx, folder.ID)
	if err != nil {
		// Continue without stats
		stats = &services.FolderStats{TotalFiles: 0, TotalSize: 0}
	}

	// Get breadcrumb path
	path, err := r.FolderService.GetFolderPath(ctx, folder.ID)
	if err != nil {
		path = []services.Folder{}
	}

	return &model.PublicFolderView{
		Folder:         toGraphQLFolder(folder),
		Breadcrumbs:    toGraphQLFolders(path),
		CanDownloadAll: true,
		Stats: &model.FolderStats{
			TotalFiles: int(stats.TotalFiles),
			TotalSize:  int(stats.TotalSize),
			FileTypes:  []*model.FileTypeCount{},
		},
	}, nil
}

func (r *queryResolver) PublicFolderContents(ctx context.Context, shareToken string, path *string) (*model.FolderContents, error) {
	// Get folder by share token
	folder, err := r.FolderService.GetFolderByShareToken(ctx, shareToken)
	if err != nil {
		return nil, fmt.Errorf("folder not found or not public")
	}

	// Get contents
	folders, files, err := r.FolderService.GetPublicFolderContents(ctx, folder.ID, path)
	if err != nil {
		return nil, err
	}

	// Calculate total size
	var totalSize int64
	for _, f := range files {
		totalSize += f.Size
	}

	return &model.FolderContents{
		Folders:   toGraphQLFolders(folders),
		Files:     toGraphQLFiles(files),
		TotalSize: int(totalSize),
		ItemCount: len(folders) + len(files),
	}, nil
}

// Folder Field Resolvers - Implementing computed fields

// Path returns the breadcrumb path from root to this folder
func (r *folderResolver) Path(ctx context.Context, obj *model.Folder) ([]*model.Folder, error) {
	folderID, err := uuid.Parse(obj.ID)
	if err != nil {
		return []*model.Folder{}, nil
	}

	path, err := r.FolderService.GetFolderPath(ctx, folderID)
	if err != nil {
		return []*model.Folder{}, nil
	}

	return toGraphQLFolders(path), nil
}

// Children returns direct child folders
func (r *folderResolver) Children(ctx context.Context, obj *model.Folder) ([]*model.Folder, error) {
	folderID, err := uuid.Parse(obj.ID)
	if err != nil {
		return []*model.Folder{}, nil
	}

	userIDStr := auth.GetUserIDFromContext(ctx)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return []*model.Folder{}, nil
	}

	folders, _, err := r.FolderService.GetFolderContents(ctx, &folderID, userID)
	if err != nil {
		return []*model.Folder{}, nil
	}

	return toGraphQLFolders(folders), nil
}

// Files returns files in this folder
func (r *folderResolver) Files(ctx context.Context, obj *model.Folder) ([]*model.File, error) {
	folderID, err := uuid.Parse(obj.ID)
	if err != nil {
		return []*model.File{}, nil
	}

	userIDStr := auth.GetUserIDFromContext(ctx)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return []*model.File{}, nil
	}

	_, files, err := r.FolderService.GetFolderContents(ctx, &folderID, userID)
	if err != nil {
		return []*model.File{}, nil
	}

	return toGraphQLFiles(files), nil
}

// IsShared returns whether the folder has an active share link
func (r *folderResolver) IsShared(ctx context.Context, obj *model.Folder) (bool, error) {
	return obj.ShareToken != nil && *obj.ShareToken != "", nil
}

// CanAccess returns whether current user can access the folder
func (r *folderResolver) CanAccess(ctx context.Context, obj *model.Folder) (bool, error) {
	folderID, err := uuid.Parse(obj.ID)
	if err != nil {
		return false, nil
	}

	userIDStr := auth.GetUserIDFromContext(ctx)
	var userID *uuid.UUID
	if userIDStr != "" {
		parsed, err := uuid.Parse(userIDStr)
		if err == nil {
			userID = &parsed
		}
	}

	return r.FolderService.CanAccessFolder(ctx, folderID, userID), nil
}

// folderResolver is the resolver for Folder field resolvers
type folderResolver struct{ *Resolver }

// Folder returns the folder resolver
func (r *Resolver) Folder() FolderResolver { return &folderResolver{r} }

// FolderResolver interface (you may need to add this to the generated code)
type FolderResolver interface {
	Path(ctx context.Context, obj *model.Folder) ([]*model.Folder, error)
	Children(ctx context.Context, obj *model.Folder) ([]*model.Folder, error)
	Files(ctx context.Context, obj *model.Folder) ([]*model.File, error)
	IsShared(ctx context.Context, obj *model.Folder) (bool, error)
	CanAccess(ctx context.Context, obj *model.Folder) (bool, error)
}
