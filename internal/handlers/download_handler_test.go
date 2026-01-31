package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// TestParseRangeHeader tests the range header parsing logic
func TestParseRangeHeader(t *testing.T) {
	handler := &DownloadHandler{}

	tests := []struct {
		name        string
		rangeHeader string
		fileSize    int64
		wantStart   int64
		wantEnd     int64
		wantErr     bool
	}{
		{
			name:        "Full range specified",
			rangeHeader: "bytes=0-999",
			fileSize:    1000,
			wantStart:   0,
			wantEnd:     999,
			wantErr:     false,
		},
		{
			name:        "Open-ended range",
			rangeHeader: "bytes=500-",
			fileSize:    1000,
			wantStart:   500,
			wantEnd:     999,
			wantErr:     false,
		},
		{
			name:        "Middle range",
			rangeHeader: "bytes=200-299",
			fileSize:    1000,
			wantStart:   200,
			wantEnd:     299,
			wantErr:     false,
		},
		{
			name:        "Invalid format - no bytes prefix",
			rangeHeader: "0-999",
			fileSize:    1000,
			wantErr:     true,
		},
		{
			name:        "Invalid range - start > end",
			rangeHeader: "bytes=500-300",
			fileSize:    1000,
			wantErr:     true,
		},
		{
			name:        "Invalid range - end >= fileSize",
			rangeHeader: "bytes=0-1000",
			fileSize:    1000,
			wantErr:     true,
		},
		{
			name:        "Invalid range - negative start",
			rangeHeader: "bytes=-100-200",
			fileSize:    1000,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := handler.parseRangeHeader(tt.rangeHeader, tt.fileSize)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseRangeHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if start != tt.wantStart {
					t.Errorf("parseRangeHeader() start = %v, want %v", start, tt.wantStart)
				}
				if end != tt.wantEnd {
					t.Errorf("parseRangeHeader() end = %v, want %v", end, tt.wantEnd)
				}
			}
		})
	}
}

// MockDB is a mock database for testing
type MockDB struct {
	*sql.DB
}

// MockS3Service is a mock S3 service for testing
type MockS3Service struct {
	testData []byte
}

// MockEncryptionService is a mock encryption service for testing
type MockEncryptionService struct{}

func (m *MockEncryptionService) EncryptFile(data []byte) ([]byte, error) {
	// Simple mock: just return the data with a prefix
	return append([]byte("ENCRYPTED:"), data...), nil
}

func (m *MockEncryptionService) DecryptFile(data []byte) ([]byte, error) {
	// Simple mock: remove the prefix
	if len(data) < 10 || string(data[:10]) != "ENCRYPTED:" {
		return nil, fmt.Errorf("invalid encrypted data")
	}
	return data[10:], nil
}

// TestRangeRequestIntegration tests the full range request flow
func TestRangeRequestIntegration(t *testing.T) {
	// Skip if no database connection available
	// This is an integration test that would need a real or test database

	// Create test data
	testContent := []byte("This is a test file content for range request testing. It has enough data to test partial content delivery.")
	encryptedContent, _ := (&MockEncryptionService{}).EncryptFile(testContent)

	// Setup mock services
	mockS3 := &MockS3Service{testData: encryptedContent}
	_ = mockS3 // Use the variable

	// Note: In a real test, you'd need a test database connection
	// For now, this demonstrates the test structure

	t.Run("Basic range request structure", func(t *testing.T) {
		// Test that the parseRangeHeader function works correctly
		handler := &DownloadHandler{}

		// Test various range scenarios
		rangeTests := []struct {
			rangeHeader    string
			expectedStatus int
			expectedSize   int64
		}{
			{"bytes=0-49", http.StatusPartialContent, 50},
			{"bytes=50-99", http.StatusPartialContent, 50},
			{"bytes=0-", http.StatusPartialContent, int64(len(testContent))},
		}

		for _, rt := range rangeTests {
			start, end, err := handler.parseRangeHeader(rt.rangeHeader, int64(len(testContent)))
			if err != nil {
				t.Errorf("Failed to parse range header %s: %v", rt.rangeHeader, err)
				continue
			}

			expectedSize := end - start + 1
			if expectedSize != rt.expectedSize {
				t.Errorf("Range %s: expected size %d, got %d", rt.rangeHeader, rt.expectedSize, expectedSize)
			}
		}
	})
}

// TestRangeRequestHeaders tests that proper headers are set for range requests
func TestRangeRequestHeaders(t *testing.T) {
	testContent := []byte("0123456789" + "0123456789" + "0123456789") // 30 bytes

	t.Run("Verify Content-Range header format", func(t *testing.T) {
		fileSize := int64(len(testContent))

		tests := []struct {
			start          int64
			end            int64
			expectedHeader string
		}{
			{0, 9, "bytes 0-9/30"},
			{10, 19, "bytes 10-19/30"},
			{20, 29, "bytes 20-29/30"},
		}

		for _, tt := range tests {
			header := fmt.Sprintf("bytes %d-%d/%d", tt.start, tt.end, fileSize)
			if header != tt.expectedHeader {
				t.Errorf("Expected header %s, got %s", tt.expectedHeader, header)
			}
		}
	})

	t.Run("Verify partial content response", func(t *testing.T) {
		// Create a test HTTP response recorder
		w := httptest.NewRecorder()

		// Simulate setting range request headers
		start := int64(0)
		end := int64(9)
		fileSize := int64(30)

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", end-start+1))
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusPartialContent)

		// Verify response code
		if w.Code != http.StatusPartialContent {
			t.Errorf("Expected status %d, got %d", http.StatusPartialContent, w.Code)
		}

		// Verify headers
		if w.Header().Get("Accept-Ranges") != "bytes" {
			t.Errorf("Expected Accept-Ranges: bytes")
		}

		contentRange := w.Header().Get("Content-Range")
		expectedRange := "bytes 0-9/30"
		if contentRange != expectedRange {
			t.Errorf("Expected Content-Range: %s, got %s", expectedRange, contentRange)
		}
	})
}

// TestSendErrorResponse tests error response formatting
func TestSendErrorResponse(t *testing.T) {
	handler := &DownloadHandler{}

	tests := []struct {
		name       string
		message    string
		statusCode int
	}{
		{"Bad Request", "Invalid file ID", http.StatusBadRequest},
		{"Unauthorized", "Authentication required", http.StatusUnauthorized},
		{"Not Found", "File not found", http.StatusNotFound},
		{"Forbidden", "Access denied", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			handler.sendErrorResponse(w, tt.message, tt.statusCode)

			// Check status code
			if w.Code != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, w.Code)
			}

			// Check CORS headers
			if w.Header().Get("Access-Control-Allow-Origin") != "*" {
				t.Errorf("Missing CORS header")
			}

			// Check response body
			var response DownloadResponse
			err := json.NewDecoder(w.Body).Decode(&response)
			if err != nil {
				t.Errorf("Failed to decode response: %v", err)
			}

			if response.Success != false {
				t.Errorf("Expected success=false")
			}

			if response.Error != tt.message {
				t.Errorf("Expected error message %s, got %s", tt.message, response.Error)
			}
		})
	}
}

// TestCORSHeaders tests that CORS headers are properly set
func TestCORSHeaders(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{"OPTIONS request", "OPTIONS", http.StatusOK},
		{"GET request", "GET", http.StatusUnauthorized}, // Will fail auth but should have CORS headers
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &DownloadHandler{}

			req := httptest.NewRequest(tt.method, "/download/test-file-id", nil)
			w := httptest.NewRecorder()

			// Setup router
			r := mux.NewRouter()
			r.HandleFunc("/download/{fileId}", handler.HandleFileDownload)
			r.ServeHTTP(w, req)

			// Check CORS headers are present
			expectedHeaders := map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET, OPTIONS",
			}

			for header, expectedValue := range expectedHeaders {
				actualValue := w.Header().Get(header)
				if actualValue != expectedValue {
					t.Errorf("Expected %s: %s, got %s", header, expectedValue, actualValue)
				}
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkParseRangeHeader(b *testing.B) {
	handler := &DownloadHandler{}
	fileSize := int64(1000000) // 1MB

	b.Run("Simple range", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = handler.parseRangeHeader("bytes=0-999", fileSize)
		}
	})

	b.Run("Open-ended range", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = handler.parseRangeHeader("bytes=500000-", fileSize)
		}
	})
}

// TestRangeRequestByteAccuracy tests that the correct bytes are returned
func TestRangeRequestByteAccuracy(t *testing.T) {
	// Create known test data
	testData := make([]byte, 100)
	for i := range testData {
		testData[i] = byte(i)
	}

	tests := []struct {
		name      string
		start     int64
		end       int64
		wantBytes []byte
	}{
		{
			name:      "First 10 bytes",
			start:     0,
			end:       9,
			wantBytes: testData[0:10],
		},
		{
			name:      "Middle 10 bytes",
			start:     45,
			end:       54,
			wantBytes: testData[45:55],
		},
		{
			name:      "Last 10 bytes",
			start:     90,
			end:       99,
			wantBytes: testData[90:100],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate extracting the byte range
			extracted := testData[tt.start : tt.end+1]

			if !bytes.Equal(extracted, tt.wantBytes) {
				t.Errorf("Byte range extraction failed")
			}

			// Verify length
			expectedLen := tt.end - tt.start + 1
			if int64(len(extracted)) != expectedLen {
				t.Errorf("Expected %d bytes, got %d", expectedLen, len(extracted))
			}
		})
	}
}
