package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type B2Service struct {
	client     *s3.Client
	bucketName string
	region     string
}

type PresignedURLs struct {
	UploadURL   string `json:"uploadUrl"`
	DownloadURL string `json:"downloadUrl"`
}

func NewB2Service() (*B2Service, error) {
	endpoint := os.Getenv("B2_S3_ENDPOINT")
	if endpoint == "" {
		return nil, fmt.Errorf("B2_S3_ENDPOINT environment variable is required")
	}

	bucketName := os.Getenv("B2_BUCKET_NAME")
	if bucketName == "" {
		return nil, fmt.Errorf("B2_BUCKET_NAME environment variable is required")
	}

	keyID := os.Getenv("B2_KEY_ID")
	applicationKey := os.Getenv("B2_APPLICATION_KEY")
	if keyID == "" || applicationKey == "" {
		return nil, fmt.Errorf("B2_KEY_ID and B2_APPLICATION_KEY environment variables are required")
	}

	region := os.Getenv("B2_REGION")
	if region == "" {
		region = "us-east-1"
	}

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keyID, applicationKey, "")),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				if service == s3.ServiceID {
					return aws.Endpoint{
						URL:               endpoint,
						HostnameImmutable: true,
						SigningRegion:     region,
					}, nil
				}
				return aws.Endpoint{}, &aws.EndpointNotFoundError{}
			},
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load B2 S3-compatible config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(options *s3.Options) {
		options.UsePathStyle = true
	})

	return &B2Service{
		client:     client,
		bucketName: bucketName,
		region:     region,
	}, nil
}

// Generate presigned URL for uploading (B2 S3-compatible)
func (s *B2Service) GeneratePresignedUploadURL(key, contentType string) (string, error) {
	presignClient := s3.NewPresignClient(s.client)

	request, err := presignClient.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.bucketName),
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

// Generate presigned URL for downloading (B2 S3-compatible)
func (s *B2Service) GeneratePresignedDownloadURL(key string) (string, error) {
	presignClient := s3.NewPresignClient(s.client)

	request, err := presignClient.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
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
func (s *B2Service) GetPresignedUploadURL(key string, contentType string, expirationMinutes int) (string, error) {
	presignClient := s3.NewPresignClient(s.client)

	request, err := presignClient.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.bucketName),
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
func (s *B2Service) GetPresignedDownloadURL(key string, expirationMinutes int) (string, error) {
	presignClient := s3.NewPresignClient(s.client)

	request, err := presignClient.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = time.Duration(expirationMinutes) * time.Minute
	})

	if err != nil {
		return "", fmt.Errorf("failed to presign download URL: %w", err)
	}

	return request.URL, nil
}

// ObjectExists checks if an object exists in B2
func (s *B2Service) ObjectExists(s3Key string) (bool, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(s3Key),
	}

	_, err := s.client.HeadObject(context.TODO(), input)
	if err != nil {
		// Check if it's a "not found" error
		if IsNotFoundError(err) {
			return false, nil // Object doesn't exist, but no error
		}
		return false, fmt.Errorf("failed to check object existence: %w", err)
	}

	return true, nil
}

// Get object metadata
func (s *B2Service) GetObjectMetadata(key string) (*s3.HeadObjectOutput, error) {
	return s.client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})
}

// Get object size (B2 S3-compatible)
func (s *B2Service) GetObjectSize(key string) (int64, error) {
	result, err := s.client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(s.bucketName),
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

// UploadObject uploads raw content to B2 (unencrypted)
func (s *B2Service) UploadObject(key string, content []byte, contentType string) error {
	_, err := s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.bucketName),
		Key:         aws.String(key),
		Body:        bytes.NewReader(content),
		ContentType: aws.String(contentType),
	})

	if err != nil {
		return fmt.Errorf("failed to upload object to B2: %w", err)
	}

	log.Printf("✅ Object uploaded to B2: b2://%s/%s", s.bucketName, key)
	return nil
}

func (s *B2Service) GetBucketName() string {
	return s.bucketName
}

// ComputeObjectHash downloads the object from B2 and computes SHA-256 hash of its content
func (s *B2Service) ComputeObjectHash(key string) (string, error) {
	// Get the object from S3
	result, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get object from B2: %w", err)
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
func (s *B2Service) GetObjectETag(key string) (string, error) {
	result, err := s.client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(s.bucketName),
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
func (s *B2Service) ComputeObjectHashStream(key string) (string, error) {
	// Get the object from S3
	result, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get object from B2: %w", err)
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
func (s *B2Service) UploadEncryptedObject(key string, encryptedContent []byte, contentType string) error {
	_, err := s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(s.bucketName),
		Key:         aws.String(key),
		Body:        bytes.NewReader(encryptedContent),
		ContentType: aws.String("application/octet-stream"), // Always use binary for encrypted files
	})
	return err
}

// DownloadAndDecryptObject downloads encrypted content from B2
func (s *B2Service) DownloadAndDecryptObject(key string) ([]byte, error) {
	result, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download object from B2: %w", err)
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
func (s *B2Service) ComputeEncryptedObjectHash(key string, encryptionService *EncryptionService) (string, error) {
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
func (s *B2Service) ComputeObjectHashAndSize(s3Key string) (string, int64, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(s3Key),
	}

	result, err := s.client.GetObject(context.TODO(), input)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get object from B2: %w", err)
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

// Add this method to download objects from B2
func (s *B2Service) DownloadObject(key string) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("B2 service not initialized")
	}

	result, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download object from B2: %w", err)
	}
	defer result.Body.Close()

	content, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object content: %w", err)
	}

	return content, nil
}

// Add this method if it doesn't exist
func (s *B2Service) DeleteObject(key string) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("B2 service not initialized")
	}

	log.Printf("🗑️ Deleting object from B2: bucket=%s, key=%s", s.bucketName, key)

	_, err := s.client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})

	if err != nil {
		return fmt.Errorf("failed to delete object from B2: %w", err)
	}

	log.Printf("✅ Object deleted from B2 successfully: %s", key)
	return nil
}
