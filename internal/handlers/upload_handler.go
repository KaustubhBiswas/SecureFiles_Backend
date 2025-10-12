package handlers

import (
	"backend/internal/auth"
	"backend/internal/services"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type UploadHandler struct {
	DB                *sql.DB
	S3Service         *services.S3Service
	EncryptionService *services.EncryptionService
}

type UploadResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	FileID      string `json:"fileId,omitempty"`
	ContentHash string `json:"contentHash,omitempty"`
	Error       string `json:"error,omitempty"`
}

func NewUploadHandler(db *sql.DB, s3Service *services.S3Service, encryptionService *services.EncryptionService) *UploadHandler {
	return &UploadHandler{
		DB:                db,
		S3Service:         s3Service,
		EncryptionService: encryptionService,
	}
}

func (h *UploadHandler) HandleFileUpload(w http.ResponseWriter, r *http.Request) {
	log.Printf("📁 File upload request received from %s", r.RemoteAddr)

	// Handle CORS preflight
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get user from context (set by auth middleware)
	claims, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		log.Printf("❌ Authentication failed: %v", err)
		h.sendErrorResponse(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	log.Printf("✅ Upload authenticated for user: %s", claims.UserID)

	// Parse multipart form
	err = r.ParseMultipartForm(100 << 20) // 100MB max
	if err != nil {
		log.Printf("❌ Failed to parse multipart form: %v", err)
		h.sendErrorResponse(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("❌ Failed to get file from form: %v", err)
		h.sendErrorResponse(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	log.Printf("📄 Processing file: %s (size: %d bytes)", header.Filename, header.Size)

	// Validate file size (100MB limit)
	if header.Size > 100*1024*1024 {
		h.sendErrorResponse(w, "File too large (max 100MB)", http.StatusBadRequest)
		return
	}

	// Read entire file content into memory
	originalFileContent, err := io.ReadAll(file)
	if err != nil {
		log.Printf("❌ Failed to read file content: %v", err)
		h.sendErrorResponse(w, "Failed to process file", http.StatusInternalServerError)
		return
	}

	// Compute SHA-256 hash of ORIGINAL content (before encryption)
	hasher := sha256.New()
	hasher.Write(originalFileContent)
	originalContentHash := hex.EncodeToString(hasher.Sum(nil))

	log.Printf("🔐 Original file content hash computed: %s", originalContentHash)

	// Check if file with same hash already exists for this user
	existingFileID, err := h.checkDuplicateFile(claims.UserID, originalContentHash)
	if err != nil {
		log.Printf("❌ Failed to check for duplicate files: %v", err)
		// Continue with upload (don't fail on duplicate check error)
	} else if existingFileID != "" {
		log.Printf("♻️ Duplicate file detected, returning existing file: %s", existingFileID)
		response := UploadResponse{
			Success:     true,
			Message:     "File already exists (duplicate content)",
			FileID:      existingFileID,
			ContentHash: originalContentHash,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// ENCRYPT FILE CONTENT BEFORE UPLOAD
	if h.EncryptionService == nil {
		log.Printf("❌ Encryption service not available")
		h.sendErrorResponse(w, "Encryption service unavailable", http.StatusInternalServerError)
		return
	}

	log.Printf("🔒 Encrypting file content...")
	encryptedFileContent, err := h.EncryptionService.EncryptFile(originalFileContent)
	if err != nil {
		log.Printf("❌ Failed to encrypt file content: %v", err)
		h.sendErrorResponse(w, "Failed to secure file", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ File content encrypted successfully (original: %d bytes -> encrypted: %d bytes)",
		len(originalFileContent), len(encryptedFileContent))

	// Check user quota before proceeding
	originalFileSize := int64(len(originalFileContent))
	var currentQuotaUsed, quotaLimit int64
	err = h.DB.QueryRow("SELECT quota_used, quota_limit FROM users WHERE id = $1", claims.UserID).
		Scan(&currentQuotaUsed, &quotaLimit)
	if err != nil {
		log.Printf("❌ Failed to get user quota: %v", err)
		h.sendErrorResponse(w, "Failed to verify quota", http.StatusInternalServerError)
		return
	}

	if currentQuotaUsed+originalFileSize > quotaLimit {
		log.Printf("❌ Quota exceeded: current=%d, file_size=%d, limit=%d", currentQuotaUsed, originalFileSize, quotaLimit)
		h.sendErrorResponse(w, fmt.Sprintf("Insufficient quota: file size %d bytes would exceed available quota of %d bytes",
			originalFileSize, quotaLimit-currentQuotaUsed), http.StatusBadRequest)
		return
	}

	// Generate unique identifiers
	fileID := uuid.New().String()
	blobID := uuid.New().String()
	ext := filepath.Ext(header.Filename)

	// Generate S3 key using original content hash but store as encrypted blob
	// Use .enc extension to indicate encrypted content
	s3Key := fmt.Sprintf("encrypted/%s/%s.enc", originalContentHash[:2], originalContentHash)

	// Get form fields
	description := r.FormValue("description")
	tagsString := r.FormValue("tags")
	isPublic := r.FormValue("isPublic") == "true"

	// Process tags
	var tags []string
	if tagsString != "" {
		rawTags := strings.Split(tagsString, ",")
		for _, tag := range rawTags {
			trimmed := strings.TrimSpace(tag)
			if trimmed != "" {
				tags = append(tags, trimmed)
			}
		}
	}
	if tags == nil {
		tags = []string{}
	}

	// Get original MIME type (store original, even though we're uploading encrypted)
	originalMimeType := header.Header.Get("Content-Type")
	if originalMimeType == "" {
		originalMimeType = http.DetectContentType(originalFileContent)
		if originalMimeType == "" {
			originalMimeType = "application/octet-stream"
		}
	}

	log.Printf("📋 File details: ID=%s, Hash=%s, OriginalMIME=%s, S3Key=%s",
		fileID, originalContentHash, originalMimeType, s3Key)

	if h.S3Service == nil {
		log.Printf("❌ S3 service not available")
		h.sendErrorResponse(w, "Storage service unavailable", http.StatusInternalServerError)
		return
	}

	// Check if encrypted blob with same hash already exists in S3
	bucketName := h.S3Service.GetBucketName()
	objectExists, err := h.S3Service.ObjectExists(s3Key)
	if err != nil {
		log.Printf("⚠️ Failed to check S3 object existence: %v", err)
		objectExists = false // Continue with upload
	}

	var s3URL string
	now := time.Now()

	if objectExists {
		log.Printf("♻️ Encrypted file with same content hash already exists in S3: %s", s3Key)
		s3URL = fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucketName, s3Key)
	} else {
		// Upload ENCRYPTED content to S3 with binary MIME type
		log.Printf("🚀 Uploading ENCRYPTED file to S3: %s", s3Key)

		err = h.S3Service.UploadObject(s3Key, encryptedFileContent, "application/octet-stream")
		if err != nil {
			log.Printf("❌ Failed to upload encrypted file to S3: %v", err)
			h.sendErrorResponse(w, "Failed to upload file to storage", http.StatusInternalServerError)
			return
		}

		s3URL = fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucketName, s3Key)
		log.Printf("✅ Encrypted file uploaded to S3: %s", s3URL)
	}

	// Insert blob record (store info about original file)
	blobQuery := `
        INSERT INTO blobs (id, content_hash, size_bytes, mime_type, storage_path, compression_type, created_at, s3_key, s3_bucket, upload_status, uploaded_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `

	_, err = h.DB.Exec(blobQuery,
		blobID,                          // $1 - id
		originalContentHash,             // $2 - content_hash (hash of ORIGINAL content)
		int64(len(originalFileContent)), // $3 - size_bytes (ORIGINAL file size)
		originalMimeType,                // $4 - mime_type (ORIGINAL MIME type)
		s3URL,                           // $5 - storage_path (S3 URL of encrypted file)
		"AES256",                        // $6 - compression_type (indicate encryption)
		now,                             // $7 - created_at
		s3Key,                           // $8 - s3_key (encrypted file key)
		bucketName,                      // $9 - s3_bucket
		"UPLOADED",                      // $10 - upload_status
		now,                             // $11 - uploaded_at
	)

	if err != nil {
		log.Printf("❌ Failed to insert blob record: %v", err)
		// Clean up S3 object if we just uploaded it and no one else references it
		if !objectExists {
			h.S3Service.DeleteObject(s3Key)
		}
		h.sendErrorResponse(w, "Failed to save file metadata", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Blob record created: %s", blobID)

	// Insert file record (with original file info)
	fileQuery := `
        INSERT INTO files (id, filename, original_filename, blob_id, owner_id, folder_id, file_size, is_public, description, tags, created_at, updated_at, deleted_at, download_count)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
    `

	uniqueFilename := fileID + ext
	_, err = h.DB.Exec(fileQuery,
		fileID,                          // $1 - id
		uniqueFilename,                  // $2 - filename
		header.Filename,                 // $3 - original_filename
		blobID,                          // $4 - blob_id
		claims.UserID,                   // $5 - owner_id
		nil,                             // $6 - folder_id
		int64(len(originalFileContent)), // $7 - file_size (ORIGINAL size)
		isPublic,                        // $8 - is_public
		description,                     // $9 - description
		pq.Array(tags),                  // $10 - tags
		now,                             // $11 - created_at
		now,                             // $12 - updated_at
		nil,                             // $13 - deleted_at
		0,                               // $14 - download_count
	)

	if err != nil {
		log.Printf("❌ Failed to insert file record: %v", err)
		// Clean up blob record and S3 object
		h.DB.Exec("DELETE FROM blobs WHERE id = $1", blobID)
		if !objectExists {
			h.S3Service.DeleteObject(s3Key)
		}
		h.sendErrorResponse(w, "Failed to save file metadata", http.StatusInternalServerError)
		return
	}

	// Update user quota
	_, err = h.DB.Exec("UPDATE users SET quota_used = quota_used + $1 WHERE id = $2", originalFileSize, claims.UserID)
	if err != nil {
		log.Printf("❌ Failed to update user quota: %v", err)
		// Clean up file and blob records and S3 object
		h.DB.Exec("DELETE FROM files WHERE id = $1", fileID)
		h.DB.Exec("DELETE FROM blobs WHERE id = $1", blobID)
		if !objectExists {
			h.S3Service.DeleteObject(s3Key)
		}
		h.sendErrorResponse(w, "Failed to update quota", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ File uploaded successfully: %s (blob: %s, hash: %s) - ENCRYPTED IN S3, quota updated",
		fileID, blobID, originalContentHash)

	response := UploadResponse{
		Success:     true,
		Message:     "File encrypted and uploaded successfully to S3",
		FileID:      fileID,
		ContentHash: originalContentHash,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Check if file with same content hash already exists for user
func (h *UploadHandler) checkDuplicateFile(ownerID, contentHash string) (string, error) {
	query := `
        SELECT f.id 
        FROM files f
        JOIN blobs b ON f.blob_id = b.id
        WHERE f.owner_id = $1 AND b.content_hash = $2 AND f.deleted_at IS NULL
        LIMIT 1
    `

	var fileID string
	err := h.DB.QueryRow(query, ownerID, contentHash).Scan(&fileID)
	if err == sql.ErrNoRows {
		return "", nil // No duplicate found
	}
	if err != nil {
		return "", err
	}

	return fileID, nil
}

func (h *UploadHandler) sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	response := UploadResponse{
		Success: false,
		Error:   message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// Helper function to detect MIME type from file content
func (h *UploadHandler) detectMimeType(file multipart.File) (string, error) {
	buffer := make([]byte, 512)
	_, err := file.Read(buffer)
	if err != nil {
		return "", err
	}

	// Reset file position
	file.Seek(0, 0)

	mimeType := http.DetectContentType(buffer)
	return mimeType, nil
}
