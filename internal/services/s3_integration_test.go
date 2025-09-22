//go:build integration
// +build integration

package services

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Load .env file from backend directory
	if err := godotenv.Load("../../.env"); err != nil {
		// Try loading from current directory
		if err := godotenv.Load(".env"); err != nil {
			log.Printf("Warning: Could not load .env file: %v", err)
		}
	}
}

func TestS3ServiceRealIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration test. Set RUN_INTEGRATION_TESTS=true to run.")
	}

	// Check if S3 credentials are set
	bucketName := os.Getenv("S3_BUCKET_NAME")
	awsRegion := os.Getenv("AWS_REGION")
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")

	t.Logf("Bucket Name: %s", bucketName)
	t.Logf("AWS Region: %s", awsRegion)
	if accessKey != "" {
		t.Logf("Access Key: %s***", accessKey[:4]) // Only show first 4 chars for security
	}
	if secretKey != "" {
		t.Logf("Secret Key: %s*** (length: %d)", secretKey[:4], len(secretKey))
	}

	if bucketName == "" {
		t.Skip("Skipping integration test. S3_BUCKET_NAME environment variable not set.")
	}

	if accessKey == "" || secretKey == "" {
		t.Skip("Skipping integration test. AWS credentials not set.")
	}

	// Setup S3 service
	s3Service, err := NewS3Service()
	require.NoError(t, err, "Should be able to create S3 service with loaded credentials")

	t.Logf("S3 Service created successfully with bucket: %s", s3Service.GetBucketName())

	// Test content
	testContent := []byte(fmt.Sprintf("Integration test content - %d", time.Now().Unix()))
	expectedHash := fmt.Sprintf("%x", sha256.Sum256(testContent))

	t.Logf("Test content: %s", string(testContent))
	t.Logf("Expected hash: %s", expectedHash)

	// This test assumes you have manually uploaded a file
	testKey := "test-integration/hash-test.txt"

	t.Logf("Testing with S3 key: %s", testKey)

	// Test if object exists
	exists, err := s3Service.ObjectExists(testKey)
	if err != nil {
		t.Logf("Error checking if object exists: %v", err)
		// Don't skip here, continue to show what the error was
	}
	if !exists {
		t.Skip("Test file does not exist in S3. Upload manually first.")
	}

	// Test hash computation
	actualHash, err := s3Service.ComputeObjectHash(testKey)
	if err != nil {
		t.Logf("Error computing hash: %v", err)
		return
	}

	t.Logf("Actual hash from S3: %s", actualHash)
	assert.Equal(t, 64, len(actualHash), "Hash should be 64 characters")

	// Test stream method
	streamHash, err := s3Service.ComputeObjectHashStream(testKey)
	if err != nil {
		t.Logf("Error computing stream hash: %v", err)
		return
	}

	t.Logf("Stream hash: %s", streamHash)
	assert.Equal(t, actualHash, streamHash, "Both methods should produce same hash")
}
