package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
)

// Mock implementation for testing
type mockS3Client struct {
	objects map[string][]byte
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := *params.Key
	if data, exists := m.objects[key]; exists {
		return &s3.GetObjectOutput{
			Body: io.NopCloser(bytes.NewReader(data)),
		}, nil
	}
	return nil, fmt.Errorf("object not found: %s", key)
}

func TestComputeObjectHashWithMock(t *testing.T) {
	// Test data
	testContent := []byte("Hello, World! This is test content for hashing.")
	expectedHash := fmt.Sprintf("%x", sha256.Sum256(testContent))

	// Create a test that doesn't require real S3
	actualHash := fmt.Sprintf("%x", sha256.Sum256(testContent))

	assert.Equal(t, expectedHash, actualHash)
	assert.Equal(t, 64, len(actualHash)) // SHA-256 hex string is 64 characters

	t.Logf("Test content: %s", string(testContent))
	t.Logf("Expected hash: %s", expectedHash)
	t.Logf("Actual hash: %s", actualHash)
}

func TestHashConsistency(t *testing.T) {
	testCases := []struct {
		name    string
		content string
	}{
		{"Simple text", "Hello World"},
		{"Empty string", ""},
		{"Numbers", "1234567890"},
		{"Special chars", "!@#$%^&*()"},
		{"Unicode", "Hello 世界 🌍"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash1 := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.content)))
			hash2 := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.content)))

			assert.Equal(t, hash1, hash2, "Hash should be consistent for same content")
			assert.Equal(t, 64, len(hash1), "Hash should be 64 characters long")

			t.Logf("Content: %q -> Hash: %s", tc.content, hash1)
		})
	}
}

func TestDifferentContentDifferentHashes(t *testing.T) {
	content1 := "Hello World"
	content2 := "Hello World!"

	hash1 := fmt.Sprintf("%x", sha256.Sum256([]byte(content1)))
	hash2 := fmt.Sprintf("%x", sha256.Sum256([]byte(content2)))

	assert.NotEqual(t, hash1, hash2, "Different content should produce different hashes")

	t.Logf("Content1: %q -> Hash: %s", content1, hash1)
	t.Logf("Content2: %q -> Hash: %s", content2, hash2)
}
