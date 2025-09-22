package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Service struct {
	client     *s3.Client
	BucketName string // Make this public (capitalized)
	region     string
}

type PresignedURLs struct {
	UploadURL   string `json:"uploadUrl"`
	DownloadURL string `json:"downloadUrl"`
}

func NewS3Service() (*S3Service, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	bucketName := os.Getenv("S3_BUCKET_NAME")
	if bucketName == "" {
		return nil, fmt.Errorf("S3_BUCKET_NAME environment variable is required")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	return &S3Service{
		client:     s3.NewFromConfig(cfg),
		BucketName: bucketName,
		region:     region,
	}, nil
}

// Generate presigned URL for uploading (using AWS SDK v2)
func (s *S3Service) GeneratePresignedUploadURL(key, contentType string) (string, error) {
	presignClient := s3.NewPresignClient(s.client)

	request, err := presignClient.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.BucketName),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = time.Duration(60) * time.Minute // 1 hour
	})

	if err != nil {
		return "", fmt.Errorf("failed to presign upload URL: %w", err)
	}

	return request.URL, nil
}

// Generate presigned URL for downloading (using AWS SDK v2)
func (s *S3Service) GeneratePresignedDownloadURL(key string) (string, error) {
	presignClient := s3.NewPresignClient(s.client)

	request, err := presignClient.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = time.Duration(60) * time.Minute // 1 hour
	})

	if err != nil {
		return "", fmt.Errorf("failed to presign download URL: %w", err)
	}

	return request.URL, nil
}

// Alternative method with custom expiration
func (s *S3Service) GetPresignedUploadURL(key string, contentType string, expirationMinutes int) (string, error) {
	presignClient := s3.NewPresignClient(s.client)

	request, err := presignClient.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.BucketName),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = time.Duration(expirationMinutes) * time.Minute
	})

	if err != nil {
		return "", fmt.Errorf("failed to presign upload URL: %w", err)
	}

	return request.URL, nil
}

// Alternative method with custom expiration
func (s *S3Service) GetPresignedDownloadURL(key string, expirationMinutes int) (string, error) {
	presignClient := s3.NewPresignClient(s.client)

	request, err := presignClient.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = time.Duration(expirationMinutes) * time.Minute
	})

	if err != nil {
		return "", fmt.Errorf("failed to presign download URL: %w", err)
	}

	return request.URL, nil
}

// ObjectExists checks if an object exists in S3
func (s *S3Service) ObjectExists(s3Key string) (bool, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(s3Key),
	}

	_, err := s.client.HeadObject(context.TODO(), input)
	if err != nil {
		// Check if it's a "not found" error
		var noSuchKey *types.NoSuchKey
		var notFound *types.NotFound
		if errors.As(err, &noSuchKey) || errors.As(err, &notFound) {
			return false, nil // Object doesn't exist, but no error
		}
		return false, fmt.Errorf("failed to check object existence: %w", err)
	}

	return true, nil
}


// Get object metadata
func (s *S3Service) GetObjectMetadata(key string) (*s3.HeadObjectOutput, error) {
	return s.client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	})
}

// Get object size (using AWS SDK v2)
func (s *S3Service) GetObjectSize(key string) (int64, error) {
	result, err := s.client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to head object: %w", err)
	}

	if result.ContentLength == nil {
		return 0, fmt.Errorf("content length not available")
	}

	return *result.ContentLength, nil
}

// UploadObject uploads raw content to S3 (unencrypted)
func (s *S3Service) UploadObject(key string, content []byte, contentType string) error {
	_, err := s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.BucketName),
		Key:         aws.String(key),
		Body:        bytes.NewReader(content),
		ContentType: aws.String(contentType),
	})

	if err != nil {
		return fmt.Errorf("failed to upload object to S3: %w", err)
	}

	log.Printf("✅ Object uploaded to S3: s3://%s/%s", s.BucketName, key)
	return nil
}

func (s *S3Service) GetBucketName() string {
	return s.BucketName
}

// ComputeObjectHash downloads the object from S3 and computes SHA-256 hash of its content
func (s *S3Service) ComputeObjectHash(key string) (string, error) {
	// Get the object from S3
	result, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer result.Body.Close()

	// Create SHA-256 hasher
	hasher := sha256.New()

	// Stream the file content and compute hash
	_, err = io.Copy(hasher, result.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read object content for hashing: %w", err)
	}

	// Get the final hash as hex string
	hashBytes := hasher.Sum(nil)
	hashHex := fmt.Sprintf("%x", hashBytes)

	return hashHex, nil
}

// Alternative method that uses ETag if you prefer (less secure but faster)
func (s *S3Service) GetObjectETag(key string) (string, error) {
	result, err := s.client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("failed to head object: %w", err)
	}

	if result.ETag == nil {
		return "", fmt.Errorf("etag not available")
	}

	// Remove quotes from ETag
	etag := strings.Trim(*result.ETag, "\"")
	return etag, nil
}

// Optional: Stream-based hash computation for very large files (memory efficient)
func (s *S3Service) ComputeObjectHashStream(key string) (string, error) {
	// Get the object from S3
	result, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer result.Body.Close()

	// Create SHA-256 hasher
	hasher := sha256.New()

	// Use a buffer to read in chunks (memory efficient for large files)
	buffer := make([]byte, 64*1024) // 64KB chunks
	for {
		n, err := result.Body.Read(buffer)
		if n > 0 {
			hasher.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read object content: %w", err)
		}
	}

	// Get the final hash as hex string
	hashBytes := hasher.Sum(nil)
	hashHex := fmt.Sprintf("%x", hashBytes)

	return hashHex, nil
}

// UploadEncryptedObject uploads encrypted content to S3
func (s *S3Service) UploadEncryptedObject(key string, encryptedContent []byte, contentType string) error {
	_, err := s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.BucketName),
		Key:         aws.String(key),
		Body:        bytes.NewReader(encryptedContent),
		ContentType: aws.String("application/octet-stream"), // Always use binary for encrypted files
	})
	return err
}

// DownloadAndDecryptObject downloads encrypted content from S3
func (s *S3Service) DownloadAndDecryptObject(key string) ([]byte, error) {
	result, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download object: %w", err)
	}
	defer result.Body.Close()

	// Read encrypted content
	encryptedContent, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted content: %w", err)
	}

	return encryptedContent, nil
}

// ComputeEncryptedObjectHash computes hash of the ORIGINAL content (before encryption)
func (s *S3Service) ComputeEncryptedObjectHash(key string, encryptionService *EncryptionService) (string, error) {
	// Download encrypted content
	encryptedContent, err := s.DownloadAndDecryptObject(key)
	if err != nil {
		return "", err
	}

	// Decrypt to get original content
	originalContent, err := encryptionService.DecryptFile(encryptedContent)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt for hashing: %w", err)
	}

	// Hash the ORIGINAL content
	hash := sha256.Sum256(originalContent)
	return fmt.Sprintf("%x", hash), nil
}

// ComputeObjectHashAndSize computes both hash and size in one operation
func (s *S3Service) ComputeObjectHashAndSize(s3Key string) (string, int64, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(s3Key),
	}

	result, err := s.client.GetObject(context.TODO(), input)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer result.Body.Close()

	hasher := sha256.New()
	size, err := io.Copy(hasher, result.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read object content: %w", err)
	}

	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	return hash, size, nil
}

// Add this method to download objects from S3
func (s *S3Service) DownloadObject(key string) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("S3 service not initialized")
	}

	result, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download object from S3: %w", err)
	}
	defer result.Body.Close()

	content, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object content: %w", err)
	}

	return content, nil
}

// Add this method if it doesn't exist
func (s *S3Service) DeleteObject(key string) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("S3 service not initialized")
	}

	log.Printf("🗑️ Deleting object from S3: bucket=%s, key=%s", s.BucketName, key)

	_, err := s.client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	})

	if err != nil {
		return fmt.Errorf("failed to delete object from S3: %w", err)
	}

	log.Printf("✅ Object deleted from S3 successfully: %s", key)
	return nil
}
