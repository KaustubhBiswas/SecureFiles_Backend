package resolvers

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"backend/graph/generated"
	"backend/graph/model"
	"backend/internal/auth"
	"backend/internal/services"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

type Resolver struct {
	DB                *sql.DB
	S3Service         *services.S3Service
	EncryptionService *services.EncryptionService
	FolderService     *services.FolderService
	BaseURL           string
	FrontendURL       string
}

func NewResolver(db *sql.DB, s3Service *services.S3Service, encryptionService *services.EncryptionService, folderService *services.FolderService, baseURL string, frontendURL string) *Resolver {
	return &Resolver{
		DB:                db,
		S3Service:         s3Service,
		EncryptionService: encryptionService,
		FolderService:     folderService,
		BaseURL:           baseURL,
		FrontendURL:       frontendURL,
	}
}

// Root resolvers
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }
func (r *Resolver) Query() generated.QueryResolver       { return &queryResolver{r} }

// func (r *Resolver) Folder() generated.FolderResolver     { return &folderResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }

// type folderResolver struct{ *Resolver }

// ========== QUERY RESOLVERS ==========

func (r *queryResolver) Me(ctx context.Context) (*model.User, error) {
	log.Printf("🔍 Me query called")

	claims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		log.Printf("❌ Me query - authentication failed: %v", err)
		return nil, fmt.Errorf("authentication required: %v", err)
	}

	log.Printf("✅ Me query - authenticated user: ID=%s, Email=%s, Role=%s", claims.UserID, claims.Email, claims.Role)

	var name, email, role string
	var quotaUsed, quotaLimit int64
	var isActive bool
	var createdAt time.Time

	query := "SELECT name, email, role, quota_used, quota_limit, is_active, created_at FROM users WHERE id = $1"
	log.Printf("🔍 Executing query for user ID: %s", claims.UserID)

	err = r.DB.QueryRow(query, claims.UserID).
		Scan(&name, &email, &role, &quotaUsed, &quotaLimit, &isActive, &createdAt)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("❌ User not found in database: %s", claims.UserID)
			return nil, fmt.Errorf("user not found")
		}
		log.Printf("❌ Database error: %v", err)
		return nil, fmt.Errorf("failed to fetch user: %v", err)
	}

	log.Printf("✅ User data retrieved: Name=%s, Email=%s, Role=%s, QuotaUsed=%d, QuotaLimit=%d",
		name, email, role, quotaUsed, quotaLimit)

	user := &model.User{
		ID:         claims.UserID,
		Name:       name,
		Email:      email,
		Role:       role,
		QuotaUsed:  int(quotaUsed),
		QuotaLimit: int(quotaLimit),
		IsActive:   isActive,
		CreatedAt:  createdAt,
	}

	log.Printf("✅ Me query completed successfully for user: %s", email)
	return user, nil
}

func (r *queryResolver) File(ctx context.Context, id string) (*model.File, error) {
	// Check if this is a public request
	isPublic, _ := ctx.Value("isPublic").(bool)

	var query string
	var args []interface{}

	if isPublic {
		// For public requests, only return public files
		query = `
			SELECT f.id, f.filename, f.original_filename, f.file_size, f.is_public, 
				   f.description, f.tags, f.download_count, f.created_at, f.updated_at,
				   b.mime_type
			FROM files f
			JOIN blobs b ON f.blob_id = b.id
			WHERE f.id = $1 AND f.is_public = true AND f.deleted_at IS NULL
		`
		args = []interface{}{id}
	} else {
		// For authenticated requests, check user ownership
		userID := auth.GetUserIDFromContext(ctx)
		if userID == "" {
			return nil, fmt.Errorf("authentication required")
		}

		query = `
			SELECT f.id, f.filename, f.original_filename, f.file_size, f.is_public, 
				   f.description, f.tags, f.download_count, f.created_at, f.updated_at,
				   b.mime_type
			FROM files f
			JOIN blobs b ON f.blob_id = b.id
			WHERE f.id = $1 AND f.owner_id = $2 AND f.deleted_at IS NULL
		`
		args = []interface{}{id, userID}
	}

	var file model.File
	var tags pq.StringArray
	var description sql.NullString

	err := r.DB.QueryRow(query, args...).Scan(
		&file.ID,
		&file.Filename,
		&file.OriginalFilename,
		&file.Size,
		&file.IsPublic,
		&description,
		&tags,
		&file.DownloadCount,
		&file.CreatedAt,
		&file.UpdatedAt,
		&file.MimeType,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found or access denied")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Handle nullable fields
	if description.Valid {
		file.Description = &description.String
	}
	file.Tags = []string(tags)
	if file.Tags == nil {
		file.Tags = []string{}
	}

	return &file, nil
}

func (r *queryResolver) Files(ctx context.Context, folderID *string, limit *int, offset *int) (*model.FileConnection, error) {
	isPublic, _ := ctx.Value("isPublic").(bool)

	// Set default values
	defaultLimit := 10
	if limit != nil && *limit > 0 {
		defaultLimit = *limit
	}

	defaultOffset := 0
	if offset != nil && *offset >= 0 {
		defaultOffset = *offset
	}

	if isPublic {
		// For public requests, only return public files, ignore folderID and user ownership
		return r.getPublicFiles(ctx, &defaultLimit, &defaultOffset)
	}

	// Existing authenticated logic
	userID := auth.GetUserIDFromContext(ctx)
	if userID == "" {
		return nil, fmt.Errorf("authentication required")
	}

	// IMPORTANT: Make sure we're filtering by the authenticated user's ID
	whereClause := "f.owner_id = $1 AND f.deleted_at IS NULL"
	args := []interface{}{userID}
	argIndex := 2

	if folderID != nil {
		whereClause += fmt.Sprintf(" AND f.folder_id = $%d", argIndex)
		args = append(args, *folderID)
		argIndex++
	} else {
		whereClause += " AND f.folder_id IS NULL" // Root folder only
	}

	// Debug: Log the user ID being used
	log.Printf("🔍 Filtering files for user ID: %s", userID)

	// Get total count for this specific user
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM files f WHERE %s", whereClause)
	var totalCount int
	err := r.DB.QueryRow(countQuery, args...).Scan(&totalCount)
	if err != nil {
		log.Printf("❌ Failed to count files: %v", err)
		return nil, fmt.Errorf("failed to count files: %v", err)
	}

	log.Printf("📊 Total files for user %s: %d", userID, totalCount)

	// Get files with pagination for this specific user
	filesQuery := fmt.Sprintf(`
        SELECT 
            f.id, f.filename, f.original_filename, f.file_size, f.is_public, 
            f.description, f.tags, f.download_count, f.created_at, f.updated_at,
            b.mime_type, f.folder_id
        FROM files f
        JOIN blobs b ON f.blob_id = b.id
        WHERE %s
        ORDER BY f.created_at DESC
        LIMIT $%d OFFSET $%d
    `, whereClause, argIndex, argIndex+1)

	args = append(args, defaultLimit, defaultOffset)

	log.Printf("🔍 Executing query: %s", filesQuery)
	log.Printf("🔍 With args: %v", args)

	rows, err := r.DB.Query(filesQuery, args...)
	if err != nil {
		log.Printf("❌ Failed to query files: %v", err)
		return nil, fmt.Errorf("failed to query files: %v", err)
	}
	defer rows.Close()

	var files []*model.File
	for rows.Next() {
		file := &model.File{}
		var tags pq.StringArray
		var description sql.NullString
		var folderID sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.Filename,
			&file.OriginalFilename,
			&file.Size,
			&file.IsPublic,
			&description,
			&tags,
			&file.DownloadCount,
			&file.CreatedAt,
			&file.UpdatedAt,
			&file.MimeType,
			&folderID,
		)
		if err != nil {
			log.Printf("❌ Failed to scan file: %v", err)
			return nil, fmt.Errorf("failed to scan file: %v", err)
		}

		// Handle nullable fields
		if description.Valid {
			file.Description = &description.String
		}
		if folderID.Valid {
			file.FolderID = &folderID.String
		}
		file.Tags = []string(tags)
		if file.Tags == nil {
			file.Tags = []string{}
		}

		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading files: %v", err)
	}

	hasNextPage := (defaultOffset + defaultLimit) < totalCount

	log.Printf("✅ Found %d files for user %s (total: %d, hasNextPage: %t)", len(files), userID, totalCount, hasNextPage)

	return &model.FileConnection{
		Nodes:       files,
		TotalCount:  totalCount,
		HasNextPage: hasNextPage,
	}, nil
}

func (r *queryResolver) getPublicFiles(ctx context.Context, limit *int, offset *int) (*model.FileConnection, error) {
	defaultLimit := 10
	if limit != nil && *limit > 0 {
		defaultLimit = *limit
	}

	defaultOffset := 0
	if offset != nil && *offset >= 0 {
		defaultOffset = *offset
	}

	// Get total count of public files
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM files WHERE is_public = true AND deleted_at IS NULL"
	err := r.DB.QueryRow(countQuery).Scan(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count public files: %v", err)
	}

	// Get public files with pagination
	filesQuery := `
		SELECT f.id, f.filename, f.original_filename, f.file_size, f.is_public, 
			   f.description, f.tags, f.download_count, f.created_at, f.updated_at,
			   b.mime_type
		FROM files f
		JOIN blobs b ON f.blob_id = b.id
		WHERE f.is_public = true AND f.deleted_at IS NULL
		ORDER BY f.created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.DB.Query(filesQuery, defaultLimit, defaultOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to query public files: %v", err)
	}
	defer rows.Close()

	var files []*model.File
	for rows.Next() {
		file := &model.File{}
		var tags pq.StringArray
		var description sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.Filename,
			&file.OriginalFilename,
			&file.Size,
			&file.IsPublic,
			&description,
			&tags,
			&file.DownloadCount,
			&file.CreatedAt,
			&file.UpdatedAt,
			&file.MimeType,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file: %v", err)
		}

		// Handle nullable fields
		if description.Valid {
			file.Description = &description.String
		}
		file.Tags = []string(tags)
		if file.Tags == nil {
			file.Tags = []string{}
		}

		files = append(files, file)
	}

	hasNextPage := (defaultOffset + defaultLimit) < totalCount

	return &model.FileConnection{
		Nodes:       files,
		TotalCount:  totalCount,
		HasNextPage: hasNextPage,
	}, nil
}

func (r *queryResolver) QuotaUsage(ctx context.Context) (*model.QuotaInfo, error) {
	log.Printf("🔍 QuotaUsage query called")

	claims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		log.Printf("❌ QuotaUsage query - authentication failed: %v", err)
		return nil, fmt.Errorf("authentication required: %v", err)
	}

	log.Printf("✅ QuotaUsage query - authenticated user: ID=%s, Email=%s", claims.UserID, claims.Email)

	var quotaUsed, quotaLimit int64
	var fileCount int

	err = r.DB.QueryRow(`
        SELECT u.quota_used, u.quota_limit,
               (SELECT COUNT(*) FROM files WHERE owner_id = u.id AND deleted_at IS NULL) as file_count
        FROM users u WHERE u.id = $1`, claims.UserID).
		Scan(&quotaUsed, &quotaLimit, &fileCount)

	if err != nil {
		log.Printf("❌ Failed to get quota usage: %v", err)
		return nil, fmt.Errorf("failed to get quota usage: %v", err)
	}

	log.Printf("📊 Raw quota data: used=%d, limit=%d, files=%d", quotaUsed, quotaLimit, fileCount)

	// Fix negative quota values by recalculating from actual files
	if quotaUsed < 0 {
		log.Printf("⚠️ Negative quota detected (%d), recalculating from actual files...", quotaUsed)

		var actualUsage int64
		err = r.DB.QueryRow(`
			SELECT COALESCE(SUM(f.file_size), 0) 
			FROM files f 
			WHERE f.owner_id = $1 AND f.deleted_at IS NULL`, claims.UserID).Scan(&actualUsage)

		if err != nil {
			log.Printf("❌ Failed to calculate actual usage: %v", err)
			return nil, fmt.Errorf("failed to calculate quota usage: %v", err)
		}

		log.Printf("🔧 Calculated actual usage: %d bytes", actualUsage)

		// Update the database with the correct quota
		_, err = r.DB.Exec("UPDATE users SET quota_used = $1 WHERE id = $2", actualUsage, claims.UserID)
		if err != nil {
			log.Printf("❌ Failed to fix quota in database: %v", err)
			// Continue with the calculated value even if DB update fails
		} else {
			log.Printf("✅ Fixed quota in database: %d -> %d", quotaUsed, actualUsage)
		}

		quotaUsed = actualUsage
	}

	var percentage float64
	if quotaLimit > 0 {
		percentage = float64(quotaUsed) / float64(quotaLimit) * 100.0
	}

	result := &model.QuotaInfo{
		Used:       int(quotaUsed),
		Limit:      int(quotaLimit),
		Percentage: percentage,
		Files:      fileCount,
	}

	log.Printf("✅ QuotaUsage query result: %+v", result)
	return result, nil
}

func (r *queryResolver) DownloadFile(ctx context.Context, id string) (*model.DownloadInfo, error) {
	isPublic, _ := ctx.Value("isPublic").(bool)

	var query string
	var args []interface{}

	if isPublic {
		// For public downloads, only allow public files
		query = `
			SELECT f.id, f.original_filename, f.file_size 
			FROM files f 
			WHERE f.id = $1 AND f.is_public = true AND f.deleted_at IS NULL
		`
		args = []interface{}{id}
	} else {
		// Existing authenticated logic
		userID := auth.GetUserIDFromContext(ctx)
		if userID == "" {
			return nil, fmt.Errorf("authentication required")
		}
		query = `
			SELECT f.id, f.original_filename, f.file_size 
			FROM files f 
			WHERE f.id = $1 AND f.owner_id = $2 AND f.deleted_at IS NULL
		`
		args = []interface{}{id, userID}
	}

	var fileID, originalFilename string
	var size int64

	err := r.DB.QueryRow(query, args...).Scan(&fileID, &originalFilename, &size)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found or access denied")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Increment download count
	updateQuery := "UPDATE files SET download_count = download_count + 1 WHERE id = $1"
	_, err = r.DB.Exec(updateQuery, fileID)
	if err != nil {
		log.Printf("Warning: failed to update download count: %v", err)
	}

	// Generate download URL
	downloadURL := fmt.Sprintf("%s/download/%s", r.BaseURL, fileID)
	if isPublic {
		downloadURL = fmt.Sprintf("%s/public/download/%s", r.BaseURL, fileID)
	}

	log.Printf("🔗 Generated download URL: %s (BaseURL: %s)", downloadURL, r.BaseURL)

	expiresAt := time.Now().Add(1 * time.Hour) // 1 hour expiry

	return &model.DownloadInfo{
		DownloadURL: downloadURL,
		ExpiresAt:   expiresAt,
		Filename:    originalFilename,
		Size:        int(size),
	}, nil
}

// ========== MUTATION RESOLVERS ==========

func (r *mutationResolver) Login(ctx context.Context, email, password string) (*model.AuthResponse, error) {
	// TEMPORARY: Hardcoded admin for testing (REMOVE IN PRODUCTION)
	if email == "admin@balkanid.com" && password == "admin123" {
		// Generate a proper UUID for the admin
		adminID := "00000000-0000-0000-0000-000000000001" // Fixed UUID for consistency
		token, err := auth.GenerateToken(adminID, email, "ADMIN")
		if err != nil {
			return nil, fmt.Errorf("failed to generate token: %v", err)
		}

		user := &model.User{
			ID:         adminID,
			Name:       "System Administrator",
			Email:      email,
			Role:       "ADMIN",
			QuotaUsed:  0,
			QuotaLimit: 1073741824, // 1GB
			IsActive:   true,
			CreatedAt:  time.Now(),
		}

		log.Printf("✅ Admin logged in successfully (TESTING MODE): %s", email)

		return &model.AuthResponse{
			Token: token,
			User:  user,
		}, nil
	}

	// Regular user login
	var userID, name, role, passwordHash string
	var quotaUsed, quotaLimit int64
	var isActive bool
	var createdAt time.Time

	err := r.DB.QueryRow(`
        SELECT id, name, role, password_hash, quota_used, quota_limit, is_active, created_at
        FROM users WHERE email = $1 AND is_active = true`, email).
		Scan(&userID, &name, &role, &passwordHash, &quotaUsed, &quotaLimit, &isActive, &createdAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	if !auth.CheckPassword(password, passwordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	token, err := auth.GenerateToken(userID, email, role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %v", err)
	}

	user := &model.User{
		ID:         userID,
		Name:       name,
		Email:      email,
		Role:       role,
		QuotaUsed:  int(quotaUsed),
		QuotaLimit: int(quotaLimit),
		IsActive:   isActive,
		CreatedAt:  createdAt,
	}

	log.Printf("✅ User logged in successfully: %s", email)

	return &model.AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

func (r *mutationResolver) Register(ctx context.Context, input model.RegisterInput) (*model.AuthResponse, error) {
	// Hash password
	hashedPassword, err := auth.HashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Insert user
	var userID string
	var createdAt time.Time
	err = r.DB.QueryRow(`
        INSERT INTO users (name, email, password_hash, role, quota_limit, quota_used, is_active)
        VALUES ($1, $2, $3, 'USER', $4, 0, true)
        RETURNING id, created_at`, input.Name, input.Email, hashedPassword, 104857600). // 100MB default
		Scan(&userID, &createdAt)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return nil, fmt.Errorf("email already exists")
		}
		return nil, fmt.Errorf("failed to register user: %v", err)
	}

	// Generate token
	token, err := auth.GenerateToken(userID, input.Email, "USER")
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %v", err)
	}

	user := &model.User{
		ID:         userID,
		Name:       input.Name,
		Email:      input.Email,
		Role:       "USER",
		QuotaUsed:  0,
		QuotaLimit: 104857600,
		IsActive:   true,
		CreatedAt:  createdAt,
	}

	log.Printf("✅ User registered successfully: %s", input.Email)

	return &model.AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

func (r *mutationResolver) RequestUpload(ctx context.Context, input model.UploadRequestInput) (*model.UploadResponse, error) {
	claims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication required")
	}

	// Validate input
	if strings.TrimSpace(input.Filename) == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}
	if strings.TrimSpace(input.MimeType) == "" {
		return nil, fmt.Errorf("mime type cannot be empty")
	}

	// Generate upload ID
	uploadID := uuid.New().String()

	// Get file extension
	fileExtension := filepath.Ext(input.Filename)
	if fileExtension == "" {
		fileExtension = getExtensionFromMimeType(input.MimeType)
	}

	// Generate S3 key
	s3Key := fmt.Sprintf("uploads/%s/%s%s", claims.UserID, uploadID, fileExtension)

	// Generate presigned URL for upload (1 hour expiry)
	uploadURL, err := r.S3Service.GeneratePresignedUploadURL(s3Key, input.MimeType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate upload URL: %v", err)
	}

	expiresAt := time.Now().Add(1 * time.Hour)

	// Save upload request to database
	var folderID interface{}
	if input.FolderID != nil {
		folderID = *input.FolderID
	}

	var description interface{}
	if input.Description != nil {
		description = *input.Description
	}

	_, err = r.DB.Exec(`
        INSERT INTO upload_requests (id, user_id, filename, original_filename, file_size, 
                                   mime_type, s3_key, upload_url, expires_at, status, 
                                   description, tags, is_public, folder_id, created_at)
        VALUES ($1, $2, $3, $4, 0, $5, $6, $7, $8, 'PENDING', $9, $10, $11, $12, NOW())`,
		uploadID, claims.UserID, input.Filename, input.Filename,
		input.MimeType, s3Key, uploadURL, expiresAt,
		description, pq.Array(input.Tags), input.IsPublic, folderID)

	if err != nil {
		return nil, fmt.Errorf("failed to save upload request: %v", err)
	}

	log.Printf("✅ Upload request created: %s for user: %s", uploadID, claims.UserID)

	return &model.UploadResponse{
		UploadID:    uploadID,
		UploadURL:   uploadURL,
		ExpiresAt:   expiresAt,
		MaxFileSize: 100 * 1024 * 1024, // 100MB limit
	}, nil
}

func (r *mutationResolver) ConfirmUpload(ctx context.Context, uploadID string) (*model.File, error) {
	claims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication required")
	}

	log.Printf("=== CONFIRMING UPLOAD: %s ===", uploadID)

	// Get upload request details
	var s3Key, filename, originalFilename, mimeType, userID string
	var expiresAt time.Time
	var folderID sql.NullString
	var description sql.NullString
	var tags pq.StringArray
	var isPublic bool

	query := `
        SELECT s3_key, filename, original_filename, mime_type, user_id, expires_at,
               folder_id, description, tags, is_public
        FROM upload_requests 
        WHERE id = $1 AND status = 'PENDING'
    `

	err = r.DB.QueryRow(query, uploadID).Scan(
		&s3Key, &filename, &originalFilename, &mimeType, &userID, &expiresAt,
		&folderID, &description, &tags, &isPublic,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("upload request not found or already processed")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Verify user ownership
	if userID != claims.UserID {
		return nil, fmt.Errorf("access denied")
	}

	// Check if upload is expired
	if time.Now().After(expiresAt) {
		return nil, fmt.Errorf("upload request expired")
	}

	// Check if file exists in S3
	exists, err := r.S3Service.ObjectExists(s3Key)
	if err != nil {
		return nil, fmt.Errorf("failed to check file in storage: %v", err)
	}

	if !exists {
		return nil, fmt.Errorf("file not uploaded to storage. Please upload the file first using the provided upload URL")
	}

	// Get file size and compute hash
	hash, size, err := r.S3Service.ComputeObjectHashAndSize(s3Key)
	if err != nil {
		return nil, fmt.Errorf("failed to compute content hash: %v", err)
	}

	// Start transaction
	tx, err := r.DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %v", err)
	}
	defer tx.Rollback()

	// Check user quota
	var currentQuotaUsed, quotaLimit int64
	err = tx.QueryRow("SELECT quota_used, quota_limit FROM users WHERE id = $1", claims.UserID).
		Scan(&currentQuotaUsed, &quotaLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to get user quota: %v", err)
	}

	if currentQuotaUsed+size > quotaLimit {
		r.S3Service.DeleteObject(s3Key) // Clean up uploaded file
		return nil, fmt.Errorf("insufficient quota: file size %d bytes would exceed available quota of %d bytes",
			size, quotaLimit-currentQuotaUsed)
	}

	// Check for existing blob with same hash (deduplication)
	var blobID string
	err = tx.QueryRow("SELECT id FROM blobs WHERE content_hash = $1", hash).Scan(&blobID)

	if err == sql.ErrNoRows {
		// New unique file - need to encrypt and store
		log.Printf("New unique file - downloading, encrypting, and storing...")

		// Download the uploaded file from S3
		uploadedContent, err := r.S3Service.DownloadObject(s3Key)
		if err != nil {
			return nil, fmt.Errorf("failed to download uploaded file: %v", err)
		}

		// Encrypt the file content
		encryptedContent, err := r.EncryptionService.EncryptFile(uploadedContent)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt file: %v", err)
		}

		// Generate new S3 key for encrypted storage
		encryptedS3Key := fmt.Sprintf("encrypted/%s/%s", claims.UserID, uploadID)

		// Upload encrypted content to S3
		err = r.S3Service.UploadEncryptedObject(encryptedS3Key, encryptedContent, "application/octet-stream")
		if err != nil {
			return nil, fmt.Errorf("failed to upload encrypted file: %v", err)
		}

		// Delete the original unencrypted file
		r.S3Service.DeleteObject(s3Key)

		// Create new blob record
		err = tx.QueryRow(`
            INSERT INTO blobs (content_hash, size_bytes, mime_type, s3_key, s3_bucket, 
                             storage_path, compression_type, upload_status, uploaded_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'AES256', 'UPLOADED', NOW(), NOW())
            RETURNING id`,
			hash, size, mimeType, encryptedS3Key, r.S3Service.GetBucketName(), encryptedS3Key).Scan(&blobID)
		if err != nil {
			return nil, fmt.Errorf("failed to create blob record: %v", err)
		}

		log.Printf("Created new encrypted blob record: %s", blobID)
	} else if err != nil {
		return nil, fmt.Errorf("database error checking for duplicate: %v", err)
	} else {
		// File with same content already exists - deduplication
		log.Printf("File with same content hash already exists: %s (blob_id: %s)", hash, blobID)
		// Delete the newly uploaded file since we already have this content
		r.S3Service.DeleteObject(s3Key)
		log.Printf("Deleted duplicate file from S3: %s", s3Key)
	}

	// Create file record
	var fileID string
	var createdAt, updatedAt time.Time
	err = tx.QueryRow(`
        INSERT INTO files (filename, original_filename, blob_id, owner_id, folder_id, 
                          file_size, is_public, description, tags, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING id, created_at, updated_at`,
		filename, originalFilename, blobID, claims.UserID, folderID, size, isPublic, description, tags).
		Scan(&fileID, &createdAt, &updatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create file record: %v", err)
	}

	// Update user quota
	_, err = tx.Exec("UPDATE users SET quota_used = quota_used + $1 WHERE id = $2", size, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to update quota: %v", err)
	}

	// Mark upload request as completed
	_, err = tx.Exec("UPDATE upload_requests SET status = 'COMPLETED', completed_at = NOW(), file_size = $2 WHERE id = $1", uploadID, size)
	if err != nil {
		return nil, fmt.Errorf("failed to update upload request: %v", err)
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("✅ File upload confirmed successfully: %s (file_id: %s)", uploadID, fileID)

	// Prepare response
	var desc *string
	if description.Valid {
		desc = &description.String
	}

	fileTags := []string(tags)
	if fileTags == nil {
		fileTags = []string{}
	}

	return &model.File{
		ID:               fileID,
		Filename:         filename,
		OriginalFilename: originalFilename,
		Size:             int(size),
		MimeType:         mimeType,
		IsPublic:         isPublic,
		Description:      desc,
		Tags:             fileTags,
		DownloadCount:    0,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}, nil
}

func (r *mutationResolver) DeleteFile(ctx context.Context, id string) (*model.DeleteResponse, error) {
	claims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		return &model.DeleteResponse{
			Success: false,
			Message: "Authentication required",
		}, nil
	}

	// Check if this is actually a "toggle public" request
	if strings.HasPrefix(id, "toggle-public:") {
		actualFileID := strings.TrimPrefix(id, "toggle-public:")
		return r.togglePublicAccess(ctx, claims.UserID, actualFileID)
	}

	log.Printf("🗑️ Delete file request: %s by user: %s", id, claims.UserID)

	tx, err := r.DB.Begin()
	if err != nil {
		log.Printf("❌ Failed to start transaction: %v", err)
		return &model.DeleteResponse{
			Success: false,
			Message: "Database error",
		}, nil
	}
	defer tx.Rollback()

	// Get file info, blob info, and verify ownership
	var ownerID, blobID, s3Key string
	var fileSize int64

	query := `
        SELECT f.owner_id, f.file_size, f.blob_id, b.s3_key
        FROM files f
        JOIN blobs b ON f.blob_id = b.id
        WHERE f.id = $1 AND f.deleted_at IS NULL
    `

	err = tx.QueryRow(query, id).Scan(&ownerID, &fileSize, &blobID, &s3Key)
	if err != nil {
		if err == sql.ErrNoRows {
			return &model.DeleteResponse{
				Success: false,
				Message: "File not found",
			}, nil
		}
		log.Printf("❌ Failed to get file info: %v", err)
		return &model.DeleteResponse{
			Success: false,
			Message: "Database error",
		}, nil
	}

	// Verify ownership
	if ownerID != claims.UserID {
		log.Printf("🚫 Access denied: user %s tried to delete file owned by %s", claims.UserID, ownerID)
		return &model.DeleteResponse{
			Success: false,
			Message: "Access denied",
		}, nil
	}

	log.Printf("📋 File info: owner=%s, size=%d, blob=%s, s3Key=%s", ownerID, fileSize, blobID, s3Key)

	// Soft delete the file record
	_, err = tx.Exec("UPDATE files SET deleted_at = NOW() WHERE id = $1", id)
	if err != nil {
		log.Printf("❌ Failed to soft delete file: %v", err)
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to delete file record",
		}, nil
	}

	// Update user quota
	_, err = tx.Exec("UPDATE users SET quota_used = quota_used - $1 WHERE id = $2", fileSize, claims.UserID)
	if err != nil {
		log.Printf("❌ Failed to update user quota: %v", err)
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to update quota",
		}, nil
	}

	// Check if this blob is still referenced by other files
	var remainingFileCount int
	err = tx.QueryRow("SELECT COUNT(*) FROM files WHERE blob_id = $1 AND deleted_at IS NULL", blobID).Scan(&remainingFileCount)
	if err != nil {
		log.Printf("❌ Failed to check remaining file references: %v", err)
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to check file references",
		}, nil
	}

	log.Printf("📊 Remaining files using blob %s: %d", blobID, remainingFileCount)

	// If no other files reference this blob, we can safely delete it from S3
	// SIMPLIFIED: We don't mark the blob as deleted in the database
	var shouldDeleteFromS3 = false
	if remainingFileCount == 0 {
		log.Printf("🧹 No other files reference blob %s, will delete from S3", blobID)
		shouldDeleteFromS3 = true
	} else {
		log.Printf("♻️ Blob %s still referenced by %d other files, keeping in S3", blobID, remainingFileCount)
	}

	// Commit transaction first
	if err = tx.Commit(); err != nil {
		log.Printf("❌ Failed to commit transaction: %v", err)
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to commit changes",
		}, nil
	}

	log.Printf("✅ Database operations completed successfully")

	// Now delete from S3 if needed (outside transaction to avoid long-running transactions)
	if shouldDeleteFromS3 && r.S3Service != nil {
		log.Printf("🗑️ Deleting encrypted file from S3: %s", s3Key)

		err = r.S3Service.DeleteObject(s3Key)
		if err != nil {
			log.Printf("⚠️ Failed to delete file from S3 (file deleted from database): %v", err)
			// Don't fail the operation - file is already deleted from database
			// S3 cleanup can be handled by a background job
		} else {
			log.Printf("✅ File successfully deleted from S3: %s", s3Key)
		}
	} else if !shouldDeleteFromS3 {
		log.Printf("♻️ Blob %s still referenced by other files, keeping in S3", blobID)
	} else {
		log.Printf("⚠️ S3 service not available, file not deleted from storage")
	}

	log.Printf("🎉 File deletion completed: %s (freed %d bytes from quota)", id, fileSize)

	return &model.DeleteResponse{
		Success: true,
		Message: "File deleted successfully",
	}, nil
}

// ========== HELPER FUNCTIONS ==========

func getExtensionFromMimeType(mimeType string) string {
	switch mimeType {
	case "application/pdf":
		return ".pdf"
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "text/plain":
		return ".txt"
	case "application/msword":
		return ".doc"
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return ".docx"
	case "application/vnd.ms-excel":
		return ".xls"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return ".xlsx"
	case "application/zip":
		return ".zip"
	case "application/json":
		return ".json"
	case "text/html":
		return ".html"
	case "text/css":
		return ".css"
	case "text/javascript":
		return ".js"
	default:
		return ""
	}
}

func (r *mutationResolver) togglePublicAccess(ctx context.Context, userID, fileID string) (*model.DeleteResponse, error) {
	// Get current public status
	var isPublic bool
	query := "SELECT is_public FROM files WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL"
	err := r.DB.QueryRow(query, fileID, userID).Scan(&isPublic)

	if err != nil {
		if err == sql.ErrNoRows {
			return &model.DeleteResponse{
				Success: false,
				Message: "File not found or access denied",
			}, nil
		}
		return &model.DeleteResponse{
			Success: false,
			Message: "Database error",
		}, nil
	}

	// Toggle public status
	newPublicStatus := !isPublic
	updateQuery := "UPDATE files SET is_public = $1 WHERE id = $2 AND owner_id = $3"
	_, err = r.DB.Exec(updateQuery, newPublicStatus, fileID, userID)

	if err != nil {
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to update file",
		}, nil
	}

	message := fmt.Sprintf("File is now %s", map[bool]string{true: "public", false: "private"}[newPublicStatus])
	if newPublicStatus {
		message += fmt.Sprintf(". Public link: http://localhost:3000/public/%s", fileID)
	}

	return &model.DeleteResponse{
		Success: true,
		Message: message,
	}, nil
}

// ToggleFileVisibility toggles the public/private visibility of a file
func (r *mutationResolver) ToggleFileVisibility(ctx context.Context, id string) (*model.File, error) {
	// Get user ID from context
	userID := auth.GetUserIDFromContext(ctx)
	if userID == "" {
		return nil, fmt.Errorf("authentication required")
	}

	// First, check if the file exists and belongs to the user
	var currentIsPublic bool
	checkQuery := `
		SELECT is_public 
		FROM files 
		WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL
	`

	err := r.DB.QueryRow(checkQuery, id, userID).Scan(&currentIsPublic)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found or access denied")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Toggle the visibility
	newIsPublic := !currentIsPublic

	// Update the file's visibility
	updateQuery := `
		UPDATE files 
		SET is_public = $1, updated_at = NOW() 
		WHERE id = $2 AND owner_id = $3
		RETURNING id, filename, original_filename, file_size, is_public, description, tags, download_count, created_at, updated_at
	`

	var file model.File
	var tags pq.StringArray
	var description sql.NullString

	err = r.DB.QueryRow(updateQuery, newIsPublic, id, userID).Scan(
		&file.ID,
		&file.Filename,
		&file.OriginalFilename,
		&file.Size,
		&file.IsPublic,
		&description,
		&tags,
		&file.DownloadCount,
		&file.CreatedAt,
		&file.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to toggle file visibility: %v", err)
	}

	// Get the mime type from blobs table
	var mimeType string
	blobQuery := `
		SELECT b.mime_type 
		FROM files f 
		JOIN blobs b ON f.blob_id = b.id 
		WHERE f.id = $1
	`
	err = r.DB.QueryRow(blobQuery, id).Scan(&mimeType)
	if err != nil {
		// If we can't get mime type, continue without it
		mimeType = "application/octet-stream"
	}
	file.MimeType = mimeType

	// Handle nullable fields
	if description.Valid {
		file.Description = &description.String
	}
	file.Tags = []string(tags)
	if file.Tags == nil {
		file.Tags = []string{}
	}

	log.Printf("✅ File visibility toggled: %s -> isPublic: %v", id, newIsPublic)
	return &file, nil
}

// GenerateShareLink creates a shareable token for public access to a file
func (r *mutationResolver) GenerateShareLink(ctx context.Context, fileID string, expiresIn *int) (*model.ShareLinkResponse, error) {
	// Get user ID from context
	userID := auth.GetUserIDFromContext(ctx)
	if userID == "" {
		return nil, fmt.Errorf("authentication required")
	}

	// Check if the file exists, belongs to the user, AND is public
	var originalFilename string
	var isPublic bool
	checkQuery := `
		SELECT original_filename, is_public 
		FROM files 
		WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL
	`

	err := r.DB.QueryRow(checkQuery, fileID, userID).Scan(&originalFilename, &isPublic)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found or access denied")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Check if the file is public - only public files can be shared
	if !isPublic {
		return nil, fmt.Errorf("only public files can be shared. Please make the file public first")
	}

	// Generate a unique share token
	shareToken := uuid.New().String()

	// Calculate expiry time (default 7 days if not specified)
	var expiresAt *time.Time
	if expiresIn != nil {
		expiry := time.Now().Add(time.Duration(*expiresIn) * time.Second)
		expiresAt = &expiry
	} else {
		expiry := time.Now().Add(7 * 24 * time.Hour) // 7 days default
		expiresAt = &expiry
	}

	// Store the share token in database
	_, err = r.DB.Exec(`
		INSERT INTO file_shares (id, file_id, owner_id, share_token, expires_at, is_active, created_at)
		VALUES ($1, $2, $3, $4, $5, true, NOW())
	`, uuid.New().String(), fileID, userID, shareToken, expiresAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create share link: %v", err)
	}

	// Generate the public share URL
	shareURL := fmt.Sprintf("%s/share/%s", r.FrontendURL, shareToken)

	log.Printf("✅ Share link generated for file %s: token=%s, expires=%v", fileID, shareToken, expiresAt)

	return &model.ShareLinkResponse{
		ShareToken: shareToken,
		ShareURL:   shareURL,
		ExpiresAt:  expiresAt,
		IsActive:   true,
	}, nil
}

// PublicFile allows access to files via share token without authentication
func (r *queryResolver) PublicFile(ctx context.Context, shareToken string) (*model.File, error) {
	// Get file info using the share token
	var fileID string
	var expiresAt sql.NullTime
	var isActive bool

	shareQuery := `
		SELECT file_id, expires_at, is_active 
		FROM file_shares 
		WHERE share_token = $1
	`

	err := r.DB.QueryRow(shareQuery, shareToken).Scan(&fileID, &expiresAt, &isActive)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid or expired share link")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Check if share link is active and not expired
	if !isActive {
		return nil, fmt.Errorf("share link has been deactivated")
	}

	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		return nil, fmt.Errorf("share link has expired")
	}

	// Get the file data
	query := `
		SELECT f.id, f.filename, f.original_filename, f.file_size, f.is_public, 
			   f.description, f.tags, f.download_count, f.created_at, f.updated_at,
			   b.mime_type
		FROM files f
		JOIN blobs b ON f.blob_id = b.id
		WHERE f.id = $1 AND f.deleted_at IS NULL
	`

	var file model.File
	var tags pq.StringArray
	var description sql.NullString

	err = r.DB.QueryRow(query, fileID).Scan(
		&file.ID,
		&file.Filename,
		&file.OriginalFilename,
		&file.Size,
		&file.IsPublic,
		&description,
		&tags,
		&file.DownloadCount,
		&file.CreatedAt,
		&file.UpdatedAt,
		&file.MimeType,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Handle nullable fields
	if description.Valid {
		file.Description = &description.String
	}
	file.Tags = []string(tags)
	if file.Tags == nil {
		file.Tags = []string{}
	}

	// CRITICAL: Check if the file is still public
	// If the file was made private after the share link was created,
	// the share link should no longer work
	if !file.IsPublic {
		return nil, fmt.Errorf("file is no longer publicly accessible")
	}

	return &file, nil
}

// PublicDownload allows downloading files via share token without authentication
func (r *queryResolver) PublicDownload(ctx context.Context, shareToken string) (*model.DownloadInfo, error) {
	// Get file info using the share token
	var fileID string
	var expiresAt sql.NullTime
	var isActive bool

	shareQuery := `
		SELECT file_id, expires_at, is_active 
		FROM file_shares 
		WHERE share_token = $1
	`

	err := r.DB.QueryRow(shareQuery, shareToken).Scan(&fileID, &expiresAt, &isActive)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid or expired share link")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Check if share link is active and not expired
	if !isActive {
		return nil, fmt.Errorf("share link has been deactivated")
	}

	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		return nil, fmt.Errorf("share link has expired")
	}

	// Get file info for download
	var originalFilename string
	var size int64
	var isPublic bool

	query := `
		SELECT original_filename, file_size, is_public 
		FROM files 
		WHERE id = $1 AND deleted_at IS NULL
	`

	err = r.DB.QueryRow(query, fileID).Scan(&originalFilename, &size, &isPublic)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// CRITICAL: Check if the file is still public
	// If the file was made private after the share link was created,
	// the download should no longer work
	if !isPublic {
		return nil, fmt.Errorf("file is no longer publicly accessible")
	}

	// Increment download count
	updateQuery := "UPDATE files SET download_count = download_count + 1 WHERE id = $1"
	_, err = r.DB.Exec(updateQuery, fileID)
	if err != nil {
		log.Printf("Warning: failed to update download count: %v", err)
	}

	// Generate download URL with share token
	downloadURL := fmt.Sprintf("%s/share/download/%s", r.BaseURL, shareToken)
	log.Printf("🔗 Generated share download URL: %s (BaseURL: %s)", downloadURL, r.BaseURL)
	expiresAtTime := time.Now().Add(1 * time.Hour) // 1 hour expiry for download URL

	return &model.DownloadInfo{
		DownloadURL: downloadURL,
		ExpiresAt:   expiresAtTime,
		Filename:    originalFilename,
		Size:        int(size),
	}, nil
}

// ========== ADMIN RESOLVERS ==========

// requireAdminAuth checks if the current user has admin role
func (r *Resolver) requireAdminAuth(ctx context.Context) (*auth.Claims, error) {
	claims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication required: %v", err)
	}

	if claims.Role != "ADMIN" {
		return nil, fmt.Errorf("admin access required")
	}

	return claims, nil
}

// AdminAllFiles returns all files in the system with uploader details (admin only)
func (r *queryResolver) AdminAllFiles(ctx context.Context, limit *int, offset *int) (*model.AdminFileConnection, error) {
	_, err := r.requireAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Set default values
	defaultLimit := 50
	if limit != nil && *limit > 0 && *limit <= 200 {
		defaultLimit = *limit
	}

	defaultOffset := 0
	if offset != nil && *offset >= 0 {
		defaultOffset = *offset
	}

	// Get total count
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM files WHERE deleted_at IS NULL"
	err = r.DB.QueryRow(countQuery).Scan(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count files: %v", err)
	}

	// Get files with owner information - simplified query to avoid column mismatch
	filesQuery := `
		SELECT 
			f.id, f.filename, f.original_filename, COALESCE(f.file_size, 0), f.is_public, 
			f.description, COALESCE(f.download_count, 0), f.created_at, f.updated_at,
			COALESCE(b.mime_type, 'application/octet-stream'),
			u.id, u.name, u.email, u.role, COALESCE(u.quota_used, 0), COALESCE(u.quota_limit, 104857600), u.is_active, u.created_at
		FROM files f
		LEFT JOIN blobs b ON f.blob_id = b.id
		LEFT JOIN users u ON f.owner_id = u.id
		WHERE f.deleted_at IS NULL
		ORDER BY f.created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.DB.Query(filesQuery, defaultLimit, defaultOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to query files: %v", err)
	}
	defer rows.Close()

	var files []*model.AdminFile
	for rows.Next() {
		file := &model.AdminFile{}
		user := &model.User{}
		var description sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.Filename,
			&file.OriginalFilename,
			&file.Size,
			&file.IsPublic,
			&description,
			&file.DownloadCount,
			&file.CreatedAt,
			&file.UpdatedAt,
			&file.MimeType,
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Role,
			&user.QuotaUsed,
			&user.QuotaLimit,
			&user.IsActive,
			&user.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file: %v", err)
		}

		// Handle nullable fields
		if description.Valid {
			file.Description = &description.String
		}

		// Handle tags - set empty array since we're not selecting it for now
		file.Tags = []string{}

		file.Owner = user
		file.TotalDownloads = file.DownloadCount

		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading files: %v", err)
	}

	hasNextPage := (defaultOffset + defaultLimit) < totalCount

	log.Printf("✅ Admin fetched %d files (total: %d, hasNextPage: %t)", len(files), totalCount, hasNextPage)

	return &model.AdminFileConnection{
		Nodes:       files,
		TotalCount:  totalCount,
		HasNextPage: hasNextPage,
	}, nil
}

// AdminAllUsers returns all users in the system (admin only)
func (r *queryResolver) AdminAllUsers(ctx context.Context, limit *int, offset *int) (*model.AdminUserConnection, error) {
	_, err := r.requireAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Set default values
	defaultLimit := 50
	if limit != nil && *limit > 0 && *limit <= 200 {
		defaultLimit = *limit
	}

	defaultOffset := 0
	if offset != nil && *offset >= 0 {
		defaultOffset = *offset
	}

	// Get total count
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM users"
	err = r.DB.QueryRow(countQuery).Scan(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count users: %v", err)
	}

	// Get users with additional stats - using COALESCE for null safety
	usersQuery := `
		SELECT 
			u.id, u.name, u.email, u.role, u.quota_used, u.quota_limit, u.is_active, u.created_at,
			COALESCE(
				(SELECT COUNT(*) FROM files WHERE owner_id = u.id AND deleted_at IS NULL), 0
			) as file_count,
			COALESCE(
				(SELECT SUM(download_count) FROM files WHERE owner_id = u.id AND deleted_at IS NULL), 0
			) as total_downloads
		FROM users u
		ORDER BY u.created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.DB.Query(usersQuery, defaultLimit, defaultOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %v", err)
	}
	defer rows.Close()

	var users []*model.AdminUser
	for rows.Next() {
		user := &model.AdminUser{}
		var fileCount, totalDownloads int

		err := rows.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Role,
			&user.QuotaUsed,
			&user.QuotaLimit,
			&user.IsActive,
			&user.CreatedAt,
			&fileCount,
			&totalDownloads,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %v", err)
		}

		user.FileCount = fileCount
		user.TotalDownloads = totalDownloads
		// LastLoginAt is optional and not tracked in current schema

		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading users: %v", err)
	}

	hasNextPage := (defaultOffset + defaultLimit) < totalCount

	log.Printf("✅ Admin fetched %d users (total: %d, hasNextPage: %t)", len(users), totalCount, hasNextPage)

	return &model.AdminUserConnection{
		Nodes:       users,
		TotalCount:  totalCount,
		HasNextPage: hasNextPage,
	}, nil
}

// AdminStats returns system-wide statistics (admin only)
func (r *queryResolver) AdminStats(ctx context.Context) (*model.AdminStats, error) {
	_, err := r.requireAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	stats := &model.AdminStats{}

	// Get basic counts - using more robust queries that handle empty tables
	query := `
		SELECT 
			(SELECT COALESCE(COUNT(*), 0) FROM users) as total_users,
			(SELECT COALESCE(COUNT(*), 0) FROM files WHERE deleted_at IS NULL) as total_files,
			(SELECT COALESCE(SUM(download_count), 0) FROM files WHERE deleted_at IS NULL) as total_downloads,
			(SELECT COALESCE(SUM(file_size), 0) FROM files WHERE deleted_at IS NULL) as total_storage,
			(SELECT COALESCE(COUNT(*), 0) FROM users WHERE is_active = true) as active_users,
			(SELECT COALESCE(COUNT(*), 0) FROM files WHERE is_public = true AND deleted_at IS NULL) as public_files,
			(SELECT COALESCE(COUNT(*), 0) FROM files WHERE created_at >= NOW() - INTERVAL '7 days' AND deleted_at IS NULL) as recent_uploads,
			(SELECT COALESCE(SUM(download_count), 0) FROM files WHERE updated_at >= NOW() - INTERVAL '7 days' AND deleted_at IS NULL) as recent_downloads
	`

	err = r.DB.QueryRow(query).Scan(
		&stats.TotalUsers,
		&stats.TotalFiles,
		&stats.TotalDownloads,
		&stats.TotalStorageUsed,
		&stats.ActiveUsers,
		&stats.PublicFiles,
		&stats.RecentUploads,
		&stats.RecentDownloads,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch admin stats: %v", err)
	}

	log.Printf("✅ Admin stats fetched: users=%d, files=%d, downloads=%d, storage=%d bytes",
		stats.TotalUsers, stats.TotalFiles, stats.TotalDownloads, stats.TotalStorageUsed)

	return stats, nil
}

// AdminUserFiles returns all files for a specific user (admin only)
func (r *queryResolver) AdminUserFiles(ctx context.Context, userID string, limit *int, offset *int) (*model.FileConnection, error) {
	_, err := r.requireAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Set default values
	defaultLimit := 50
	if limit != nil && *limit > 0 && *limit <= 200 {
		defaultLimit = *limit
	}

	defaultOffset := 0
	if offset != nil && *offset >= 0 {
		defaultOffset = *offset
	}

	// Verify user exists
	var userName string
	err = r.DB.QueryRow("SELECT name FROM users WHERE id = $1", userID).Scan(&userName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Get total count for this user
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM files WHERE owner_id = $1 AND deleted_at IS NULL"
	err = r.DB.QueryRow(countQuery, userID).Scan(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count user files: %v", err)
	}

	// Get files for this user
	filesQuery := `
		SELECT 
			f.id, f.filename, f.original_filename, f.file_size, f.is_public, 
			f.description, f.tags, f.download_count, f.created_at, f.updated_at,
			b.mime_type
		FROM files f
		JOIN blobs b ON f.blob_id = b.id
		WHERE f.owner_id = $1 AND f.deleted_at IS NULL
		ORDER BY f.created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.DB.Query(filesQuery, userID, defaultLimit, defaultOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to query user files: %v", err)
	}
	defer rows.Close()

	var files []*model.File
	for rows.Next() {
		file := &model.File{}
		var tags pq.StringArray
		var description sql.NullString

		err := rows.Scan(
			&file.ID,
			&file.Filename,
			&file.OriginalFilename,
			&file.Size,
			&file.IsPublic,
			&description,
			&tags,
			&file.DownloadCount,
			&file.CreatedAt,
			&file.UpdatedAt,
			&file.MimeType,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan file: %v", err)
		}

		// Handle nullable fields
		if description.Valid {
			file.Description = &description.String
		}
		file.Tags = []string(tags)
		if file.Tags == nil {
			file.Tags = []string{}
		}

		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading files: %v", err)
	}

	hasNextPage := (defaultOffset + defaultLimit) < totalCount

	log.Printf("✅ Admin fetched %d files for user %s (%s), total: %d", len(files), userName, userID, totalCount)

	return &model.FileConnection{
		Nodes:       files,
		TotalCount:  totalCount,
		HasNextPage: hasNextPage,
	}, nil
}

// AdminDeleteFile allows admin to delete any file in the system
func (r *mutationResolver) AdminDeleteFile(ctx context.Context, fileID string) (*model.DeleteResponse, error) {
	_, err := r.requireAdminAuth(ctx)
	if err != nil {
		return &model.DeleteResponse{
			Success: false,
			Message: "Admin access required",
		}, nil
	}

	log.Printf("🗑️ Admin delete file request: %s", fileID)

	tx, err := r.DB.Begin()
	if err != nil {
		return &model.DeleteResponse{
			Success: false,
			Message: "Database error",
		}, nil
	}
	defer tx.Rollback()

	// Get file info and owner
	var ownerID, blobID, s3Key, ownerName string
	var fileSize int64

	query := `
		SELECT f.owner_id, f.file_size, f.blob_id, b.s3_key, u.name
		FROM files f
		JOIN blobs b ON f.blob_id = b.id
		JOIN users u ON f.owner_id = u.id
		WHERE f.id = $1 AND f.deleted_at IS NULL
	`

	err = tx.QueryRow(query, fileID).Scan(&ownerID, &fileSize, &blobID, &s3Key, &ownerName)
	if err != nil {
		if err == sql.ErrNoRows {
			return &model.DeleteResponse{
				Success: false,
				Message: "File not found",
			}, nil
		}
		return &model.DeleteResponse{
			Success: false,
			Message: "Database error",
		}, nil
	}

	log.Printf("📋 Admin deleting file: owner=%s (%s), size=%d, blob=%s", ownerName, ownerID, fileSize, blobID)

	// Soft delete the file record
	_, err = tx.Exec("UPDATE files SET deleted_at = NOW() WHERE id = $1", fileID)
	if err != nil {
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to delete file record",
		}, nil
	}

	// Update owner's quota
	_, err = tx.Exec("UPDATE users SET quota_used = quota_used - $1 WHERE id = $2", fileSize, ownerID)
	if err != nil {
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to update quota",
		}, nil
	}

	// Check if this blob is still referenced by other files
	var remainingFileCount int
	err = tx.QueryRow("SELECT COUNT(*) FROM files WHERE blob_id = $1 AND deleted_at IS NULL", blobID).Scan(&remainingFileCount)
	if err != nil {
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to check file references",
		}, nil
	}

	// Commit transaction first
	if err = tx.Commit(); err != nil {
		return &model.DeleteResponse{
			Success: false,
			Message: "Failed to commit changes",
		}, nil
	}

	// Delete from S3 if needed (outside transaction)
	if remainingFileCount == 0 && r.S3Service != nil {
		log.Printf("🗑️ Admin deleting file from S3: %s", s3Key)
		err = r.S3Service.DeleteObject(s3Key)
		if err != nil {
			log.Printf("⚠️ Failed to delete file from S3: %v", err)
		}
	}

	log.Printf("🎉 Admin successfully deleted file: %s (freed %d bytes from user %s)", fileID, fileSize, ownerName)

	return &model.DeleteResponse{
		Success: true,
		Message: fmt.Sprintf("File deleted successfully (freed %d bytes from %s's quota)", fileSize, ownerName),
	}, nil
}

// AdminToggleUserStatus allows admin to activate/deactivate users
func (r *mutationResolver) AdminToggleUserStatus(ctx context.Context, userID string) (*model.User, error) {
	_, err := r.requireAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	// Get current status
	var currentStatus bool
	var name, email, role string
	var quotaUsed, quotaLimit int64
	var createdAt time.Time

	query := "SELECT name, email, role, quota_used, quota_limit, is_active, created_at FROM users WHERE id = $1"
	err = r.DB.QueryRow(query, userID).Scan(&name, &email, &role, &quotaUsed, &quotaLimit, &currentStatus, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Don't allow deactivating other admins
	if role == "ADMIN" {
		return nil, fmt.Errorf("cannot deactivate admin users")
	}

	// Toggle status
	newStatus := !currentStatus
	_, err = r.DB.Exec("UPDATE users SET is_active = $1 WHERE id = $2", newStatus, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to update user status: %v", err)
	}

	log.Printf("✅ Admin toggled user status: %s (%s) -> isActive: %v", name, email, newStatus)

	return &model.User{
		ID:         userID,
		Name:       name,
		Email:      email,
		Role:       role,
		QuotaUsed:  int(quotaUsed),
		QuotaLimit: int(quotaLimit),
		IsActive:   newStatus,
		CreatedAt:  createdAt,
	}, nil
}

// AdminUpdateUserQuota allows admin to change user quotas
func (r *mutationResolver) AdminUpdateUserQuota(ctx context.Context, userID string, newQuota int) (*model.User, error) {
	_, err := r.requireAdminAuth(ctx)
	if err != nil {
		return nil, err
	}

	if newQuota < 0 {
		return nil, fmt.Errorf("quota cannot be negative")
	}

	// Get current user info
	var name, email, role string
	var quotaUsed, currentQuotaLimit int64
	var isActive bool
	var createdAt time.Time

	query := "SELECT name, email, role, quota_used, quota_limit, is_active, created_at FROM users WHERE id = $1"
	err = r.DB.QueryRow(query, userID).Scan(&name, &email, &role, &quotaUsed, &currentQuotaLimit, &isActive, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Check if new quota is less than currently used quota
	if int64(newQuota) < quotaUsed {
		return nil, fmt.Errorf("new quota (%d bytes) cannot be less than currently used quota (%d bytes)", newQuota, quotaUsed)
	}

	// Update quota
	_, err = r.DB.Exec("UPDATE users SET quota_limit = $1 WHERE id = $2", newQuota, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to update user quota: %v", err)
	}

	log.Printf("✅ Admin updated user quota: %s (%s) %d -> %d bytes", name, email, currentQuotaLimit, newQuota)

	return &model.User{
		ID:         userID,
		Name:       name,
		Email:      email,
		Role:       role,
		QuotaUsed:  int(quotaUsed),
		QuotaLimit: newQuota,
		IsActive:   isActive,
		CreatedAt:  createdAt,
	}, nil
}

// UpdateFile allows updating file metadata (admin or owner)
func (r *mutationResolver) UpdateFile(ctx context.Context, id string, input model.UpdateFileInput) (*model.File, error) {
	claims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication required: %v", err)
	}

	// Check if user is admin or file owner
	var ownerID string
	checkQuery := "SELECT owner_id FROM files WHERE id = $1 AND deleted_at IS NULL"
	err = r.DB.QueryRow(checkQuery, id).Scan(&ownerID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Only admin or file owner can update
	if claims.Role != "ADMIN" && ownerID != claims.UserID {
		return nil, fmt.Errorf("access denied")
	}

	// Build update query dynamically
	updates := []string{}
	args := []interface{}{}
	argIndex := 1

	if input.Description != nil {
		updates = append(updates, fmt.Sprintf("description = $%d", argIndex))
		args = append(args, *input.Description)
		argIndex++
	}

	if input.Tags != nil {
		updates = append(updates, fmt.Sprintf("tags = $%d", argIndex))
		args = append(args, pq.Array(input.Tags))
		argIndex++
	}

	if input.IsPublic != nil {
		updates = append(updates, fmt.Sprintf("is_public = $%d", argIndex))
		args = append(args, *input.IsPublic)
		argIndex++
	}

	if len(updates) == 0 {
		return nil, fmt.Errorf("no updates provided")
	}

	updates = append(updates, "updated_at = NOW()")
	updateQuery := fmt.Sprintf("UPDATE files SET %s WHERE id = $%d", strings.Join(updates, ", "), argIndex)
	args = append(args, id)

	_, err = r.DB.Exec(updateQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update file: %v", err)
	}

	// Return updated file by calling the query resolver
	qr := &queryResolver{r.Resolver}
	return qr.File(ctx, id)
}
