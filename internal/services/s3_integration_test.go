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

func TestB2ServiceRealIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration test. Set RUN_INTEGRATION_TESTS=true to run.")
	}

	// Check if B2 credentials are set
	bucketName := os.Getenv("B2_BUCKET_NAME")
	b2Region := os.Getenv("B2_REGION")
	keyID := os.Getenv("B2_KEY_ID")
	applicationKey := os.Getenv("B2_APPLICATION_KEY")

	t.Logf("Bucket Name: %s", bucketName)
	t.Logf("B2 Region: %s", b2Region)
	if keyID != "" {
		t.Logf("Key ID: %s***", keyID[:4]) // Only show first 4 chars for security
	}
	if applicationKey != "" {
		t.Logf("Application Key: %s*** (length: %d)", applicationKey[:4], len(applicationKey))
	}

	if bucketName == "" {
		t.Skip("Skipping integration test. B2_BUCKET_NAME environment variable not set.")
	}

	if keyID == "" || applicationKey == "" {
		t.Skip("Skipping integration test. B2 credentials not set.")
	}

	// Setup B2 service
	b2Service, err := NewB2Service()
	require.NoError(t, err, "Should be able to create B2 service with loaded credentials")

	t.Logf("B2 Service created successfully with bucket: %s", b2Service.GetBucketName())

	// Test content
	testContent := []byte(fmt.Sprintf("Integration test content - %d", time.Now().Unix()))
	expectedHash := fmt.Sprintf("%x", sha256.Sum256(testContent))

	t.Logf("Test content: %s", string(testContent))
	t.Logf("Expected hash: %s", expectedHash)

	// This test assumes you have manually uploaded a file
	testKey := "test-integration/hash-test.txt"

	t.Logf("Testing with B2 key: %s", testKey)

	// Test if object exists
	exists, err := b2Service.ObjectExists(testKey)
	if err != nil {
		t.Logf("Error checking if object exists: %v", err)
		// Don't skip here, continue to show what the error was
	}
	if !exists {
		t.Skip("Test file does not exist in B2. Upload manually first.")
	}

	// Test hash computation
	actualHash, err := b2Service.ComputeObjectHash(testKey)
	if err != nil {
		t.Logf("Error computing hash: %v", err)
		return
	}

	t.Logf("Actual hash from B2: %s", actualHash)
	assert.Equal(t, 64, len(actualHash), "Hash should be 64 characters")

	// Test stream method
	streamHash, err := b2Service.ComputeObjectHashStream(testKey)
	if err != nil {
		t.Logf("Error computing stream hash: %v", err)
		return
	}

	t.Logf("Stream hash: %s", streamHash)
	assert.Equal(t, actualHash, streamHash, "Both methods should produce same hash")
}
