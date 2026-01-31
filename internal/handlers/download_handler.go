package handlers

import (
	"backend/internal/auth"
	"backend/internal/services"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// DownloadHandler handles secure file downloads.
type DownloadHandler struct {
	DB                *sql.DB
	S3Service         *services.S3Service
	EncryptionService *services.EncryptionService
}

// NewDownloadHandler constructs a DownloadHandler.
func NewDownloadHandler(db *sql.DB, s3Service *services.S3Service, encryptionService *services.EncryptionService) *DownloadHandler {
	return &DownloadHandler{
		DB:                db,
		S3Service:         s3Service,
		EncryptionService: encryptionService,
	}
}

// DownloadResponse represents the response for a download request.
type DownloadResponse struct {
	Success     bool   `json:"success"`
	DownloadURL string `json:"downloadUrl,omitempty"`
	Filename    string `json:"filename,omitempty"`
	Size        int64  `json:"size,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
	Error       string `json:"error,omitempty"`
	ExpiresIn   int    `json:"expiresIn,omitempty"` // seconds
}

// HandleFileDownload downloads the file, checks permissions, and returns a presigned URL for the client.
func (h *DownloadHandler) HandleFileDownload(w http.ResponseWriter, r *http.Request) {
	log.Printf("📥 File download request received from %s", r.RemoteAddr)

	// Handle CORS preflight requests
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get file ID from URL
	vars := mux.Vars(r)
	fileID := vars["fileId"]
	if fileID == "" {
		h.sendErrorResponse(w, "File ID is required", http.StatusBadRequest)
		return
	}

	// Get user from context (set by auth middleware)
	claims, err := auth.GetUserFromContext(r.Context())
	if err != nil {
		log.Printf("❌ Authentication failed: %v", err)
		h.sendErrorResponse(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	log.Printf("✅ Download authenticated for user: %s, file: %s", claims.UserID, fileID)

	// Get file and blob information
	query := `
        SELECT 
            f.id, f.filename, f.original_filename, f.owner_id, f.file_size, f.is_public,
            b.id, b.content_hash, b.size_bytes, b.mime_type, b.s3_key, b.s3_bucket
        FROM files f
        JOIN blobs b ON f.blob_id = b.id
        WHERE f.id = $1 AND f.deleted_at IS NULL
    `

	var file struct {
		ID               string
		Filename         string
		OriginalFilename string
		OwnerID          string
		FileSize         int64
		IsPublic         bool
		BlobID           string
		ContentHash      string
		SizeBytes        int64
		MimeType         string
		S3Key            string
		S3Bucket         string
	}

	err = h.DB.QueryRow(query, fileID).Scan(
		&file.ID, &file.Filename, &file.OriginalFilename, &file.OwnerID, &file.FileSize, &file.IsPublic,
		&file.BlobID, &file.ContentHash, &file.SizeBytes, &file.MimeType, &file.S3Key, &file.S3Bucket,
	)

	if err == sql.ErrNoRows {
		h.sendErrorResponse(w, "File not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("❌ Failed to query file: %v", err)
		h.sendErrorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Check permissions
	if !file.IsPublic && file.OwnerID != claims.UserID {
		// Check if file is shared with this user
		hasAccess, err := h.checkFileAccess(claims.UserID, fileID)
		if err != nil {
			log.Printf("❌ Failed to check file access: %v", err)
			h.sendErrorResponse(w, "Access check failed", http.StatusInternalServerError)
			return
		}
		if !hasAccess {
			log.Printf("🚫 Access denied for user %s to file %s", claims.UserID, fileID)
			h.sendErrorResponse(w, "Access denied", http.StatusForbidden)
			return
		}
	}

	log.Printf("✅ File access granted: %s", file.OriginalFilename)

	// Check if this is a range request (for video/audio streaming)
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		h.handleRangeRequest(w, r, &file, claims.UserID, fileID)
		return
	}

	if h.S3Service == nil {
		log.Printf("❌ S3 service not available")
		h.sendErrorResponse(w, "Storage service unavailable", http.StatusInternalServerError)
		return
	}

	if h.EncryptionService == nil {
		log.Printf("❌ Encryption service not available")
		h.sendErrorResponse(w, "Encryption service unavailable", http.StatusInternalServerError)
		return
	}

	// Download encrypted content from S3
	log.Printf("📥 Downloading encrypted file from S3: %s", file.S3Key)
	encryptedContent, err := h.S3Service.DownloadObject(file.S3Key)
	if err != nil {
		log.Printf("❌ Failed to download from S3: %v", err)
		h.sendErrorResponse(w, "Failed to retrieve file", http.StatusInternalServerError)
		return
	}

	// Decrypt the content
	log.Printf("🔓 Decrypting file content...")
	originalContent, err := h.EncryptionService.DecryptFile(encryptedContent)
	if err != nil {
		log.Printf("❌ Failed to decrypt file: %v", err)
		h.sendErrorResponse(w, "Failed to decrypt file", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ File decrypted successfully (encrypted: %d bytes -> original: %d bytes)",
		len(encryptedContent), len(originalContent))

	// Update download count
	_, err = h.DB.Exec("UPDATE files SET download_count = download_count + 1 WHERE id = $1", fileID)
	if err != nil {
		log.Printf("⚠️ Failed to update download count: %v", err)
		// Don't fail the download for this
	}

	// Serve the decrypted file directly
	// Set CORS headers for cross-origin requests
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Range")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, Content-Length, Content-Type, Accept-Ranges")
	w.Header().Set("Accept-Ranges", "bytes")

	w.Header().Set("Content-Type", file.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", file.OriginalFilename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(originalContent)))

	log.Printf("✅ Serving decrypted file: %s (%d bytes)", file.OriginalFilename, len(originalContent))

	// Write the decrypted content
	_, err = w.Write(originalContent)
	if err != nil {
		log.Printf("❌ Failed to write response: %v", err)
	}
}

// HandlePublicFileDownload handles downloads via share token without authentication
func (h *DownloadHandler) HandlePublicFileDownload(w http.ResponseWriter, r *http.Request) {
	log.Printf("📥 Public file download request received from %s", r.RemoteAddr)

	// Handle CORS preflight requests
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get share token from URL
	vars := mux.Vars(r)
	shareToken := vars["shareToken"]
	if shareToken == "" {
		h.sendErrorResponse(w, "Share token is required", http.StatusBadRequest)
		return
	}

	// Get file info using the share token
	var fileID string
	var expiresAt sql.NullTime
	var isActive bool

	shareQuery := `
		SELECT file_id, expires_at, is_active 
		FROM file_shares 
		WHERE share_token = $1
	`

	err := h.DB.QueryRow(shareQuery, shareToken).Scan(&fileID, &expiresAt, &isActive)
	if err != nil {
		if err == sql.ErrNoRows {
			h.sendErrorResponse(w, "Invalid or expired share link", http.StatusNotFound)
		} else {
			h.sendErrorResponse(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	// Check if share link is active and not expired
	if !isActive {
		h.sendErrorResponse(w, "Share link has been deactivated", http.StatusForbidden)
		return
	}

	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		h.sendErrorResponse(w, "Share link has expired", http.StatusGone)
		return
	}

	// Get file information
	var file struct {
		ID               string
		Filename         string
		OriginalFilename string
		Size             int64
		MimeType         string
		BlobID           string
		S3Key            string
		IsPublic         bool
	}

	query := `
		SELECT f.id, f.filename, f.original_filename, f.file_size, 
			   b.mime_type, b.id as blob_id, b.s3_key, f.is_public
		FROM files f
		JOIN blobs b ON f.blob_id = b.id
		WHERE f.id = $1 AND f.deleted_at IS NULL
	`

	err = h.DB.QueryRow(query, fileID).Scan(
		&file.ID, &file.Filename, &file.OriginalFilename,
		&file.Size, &file.MimeType, &file.BlobID, &file.S3Key, &file.IsPublic,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			h.sendErrorResponse(w, "File not found", http.StatusNotFound)
		} else {
			h.sendErrorResponse(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	// CRITICAL: Check if the file is still public
	// If the file was made private after the share link was created,
	// the download should no longer work
	if !file.IsPublic {
		h.sendErrorResponse(w, "File is no longer publicly accessible", http.StatusForbidden)
		return
	}

	log.Printf("📁 Processing public download for file: %s (size: %d bytes)", file.OriginalFilename, file.Size)

	// Check if this is a range request (for video/audio streaming)
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		h.handlePublicRangeRequest(w, r, &file, shareToken, fileID)
		return
	}

	// Download file from S3
	encryptedContent, err := h.S3Service.DownloadObject(file.S3Key)
	if err != nil {
		log.Printf("❌ Failed to download from S3: %v", err)
		h.sendErrorResponse(w, "Failed to download file", http.StatusInternalServerError)
		return
	}

	log.Printf("📦 Downloaded encrypted file from S3: %s (%d bytes)", file.S3Key, len(encryptedContent))

	// Decrypt the file content
	originalContent, err := h.EncryptionService.DecryptFile(encryptedContent)
	if err != nil {
		log.Printf("❌ Failed to decrypt file content: %v", err)
		h.sendErrorResponse(w, "Failed to decrypt file", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ File decrypted successfully (encrypted: %d bytes -> original: %d bytes)",
		len(encryptedContent), len(originalContent))

	// Update download count
	_, err = h.DB.Exec("UPDATE files SET download_count = download_count + 1 WHERE id = $1", fileID)
	if err != nil {
		log.Printf("⚠️ Failed to update download count: %v", err)
		// Don't fail the download for this
	}

	// Serve the decrypted file directly
	// Set CORS headers for cross-origin requests
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Range")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, Content-Length, Content-Type, Accept-Ranges")
	w.Header().Set("Accept-Ranges", "bytes")

	w.Header().Set("Content-Type", file.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", file.OriginalFilename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(originalContent)))

	log.Printf("✅ Serving decrypted public file: %s (%d bytes)", file.OriginalFilename, len(originalContent))

	// Write the decrypted content
	_, err = w.Write(originalContent)
	if err != nil {
		log.Printf("❌ Failed to write response: %v", err)
	}
}

// Check if user has access to file (implement sharing logic here)
func (h *DownloadHandler) checkFileAccess(userID, fileID string) (bool, error) {
	// For now, just check if file is shared (you can implement your sharing table logic)
	query := `
        SELECT COUNT(*) 
        FROM shares 
        WHERE file_id = $1 AND shared_with_user_id = $2 AND deleted_at IS NULL
    `

	var count int
	err := h.DB.QueryRow(query, fileID, userID).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (h *DownloadHandler) sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	response := DownloadResponse{
		Success: false,
		Error:   message,
	}

	// Set CORS headers for error responses too
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// parseRangeHeader parses the Range header and returns start and end byte positions
func (h *DownloadHandler) parseRangeHeader(rangeHeader string, fileSize int64) (start int64, end int64, err error) {
	// Range header format: "bytes=start-end" or "bytes=start-"
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, fmt.Errorf("invalid range header format")
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(rangeSpec, "-")

	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range specification")
	}

	// Parse start position
	if parts[0] != "" {
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid start position: %v", err)
		}
	}

	// Parse end position (optional)
	if parts[1] != "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid end position: %v", err)
		}
	} else {
		// If end is not specified, read to end of file
		end = fileSize - 1
	}

	// Validate range
	if start < 0 || end >= fileSize || start > end {
		return 0, 0, fmt.Errorf("invalid range: start=%d, end=%d, fileSize=%d", start, end, fileSize)
	}

	return start, end, nil
}

// handleRangeRequest handles HTTP range requests for authenticated downloads
func (h *DownloadHandler) handleRangeRequest(w http.ResponseWriter, r *http.Request, file *struct {
	ID               string
	Filename         string
	OriginalFilename string
	OwnerID          string
	FileSize         int64
	IsPublic         bool
	BlobID           string
	ContentHash      string
	SizeBytes        int64
	MimeType         string
	S3Key            string
	S3Bucket         string
}, userID, fileID string) {
	rangeHeader := r.Header.Get("Range")
	log.Printf("📊 Processing range request: %s for file: %s", rangeHeader, file.OriginalFilename)

	// Download and decrypt the full file first
	// Note: For production, consider implementing byte-range decryption if possible
	encryptedContent, err := h.S3Service.DownloadObject(file.S3Key)
	if err != nil {
		log.Printf("❌ Failed to download from S3: %v", err)
		h.sendErrorResponse(w, "Failed to retrieve file", http.StatusInternalServerError)
		return
	}

	originalContent, err := h.EncryptionService.DecryptFile(encryptedContent)
	if err != nil {
		log.Printf("❌ Failed to decrypt file: %v", err)
		h.sendErrorResponse(w, "Failed to decrypt file", http.StatusInternalServerError)
		return
	}

	fileSize := int64(len(originalContent))

	// Parse range header
	start, end, err := h.parseRangeHeader(rangeHeader, fileSize)
	if err != nil {
		log.Printf("❌ Invalid range header: %v", err)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
		h.sendErrorResponse(w, "Invalid Range header", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	contentLength := end - start + 1
	log.Printf("✅ Serving range: bytes %d-%d/%d (%d bytes)", start, end, fileSize, contentLength)

	// Update download count (only once per unique request)
	_, err = h.DB.Exec("UPDATE files SET download_count = download_count + 1 WHERE id = $1", fileID)
	if err != nil {
		log.Printf("⚠️ Failed to update download count: %v", err)
	}

	// Set headers for partial content response
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Range")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Content-Type, Accept-Ranges")
	w.Header().Set("Content-Type", file.MimeType)
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent) // 206

	// Write the requested byte range
	_, err = w.Write(originalContent[start : end+1])
	if err != nil {
		log.Printf("❌ Failed to write range response: %v", err)
	}
}

// handlePublicRangeRequest handles HTTP range requests for public downloads
func (h *DownloadHandler) handlePublicRangeRequest(w http.ResponseWriter, r *http.Request, file *struct {
	ID               string
	Filename         string
	OriginalFilename string
	Size             int64
	MimeType         string
	BlobID           string
	S3Key            string
	IsPublic         bool
}, shareToken, fileID string) {
	rangeHeader := r.Header.Get("Range")
	log.Printf("📊 Processing public range request: %s for file: %s", rangeHeader, file.OriginalFilename)

	// Download and decrypt the full file
	encryptedContent, err := h.S3Service.DownloadObject(file.S3Key)
	if err != nil {
		log.Printf("❌ Failed to download from S3: %v", err)
		h.sendErrorResponse(w, "Failed to retrieve file", http.StatusInternalServerError)
		return
	}

	originalContent, err := h.EncryptionService.DecryptFile(encryptedContent)
	if err != nil {
		log.Printf("❌ Failed to decrypt file: %v", err)
		h.sendErrorResponse(w, "Failed to decrypt file", http.StatusInternalServerError)
		return
	}

	fileSize := int64(len(originalContent))

	// Parse range header
	start, end, err := h.parseRangeHeader(rangeHeader, fileSize)
	if err != nil {
		log.Printf("❌ Invalid range header: %v", err)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
		h.sendErrorResponse(w, "Invalid Range header", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	contentLength := end - start + 1
	log.Printf("✅ Serving public range: bytes %d-%d/%d (%d bytes)", start, end, fileSize, contentLength)

	// Update download count
	_, err = h.DB.Exec("UPDATE files SET download_count = download_count + 1 WHERE id = $1", fileID)
	if err != nil {
		log.Printf("⚠️ Failed to update download count: %v", err)
	}

	// Set headers for partial content response
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Range")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Content-Type, Accept-Ranges")
	w.Header().Set("Content-Type", file.MimeType)
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent) // 206

	// Write the requested byte range
	_, err = w.Write(originalContent[start : end+1])
	if err != nil {
		log.Printf("❌ Failed to write range response: %v", err)
	}
}
