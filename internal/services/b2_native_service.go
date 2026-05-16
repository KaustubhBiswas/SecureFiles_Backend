package services

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type b2AuthorizeResponse struct {
	AccountID          string `json:"accountId"`
	AuthorizationToken string `json:"authorizationToken"`
	APIURL             string `json:"apiUrl"`
	DownloadURL        string `json:"downloadUrl"`
	Allowed            struct {
		BucketID   string `json:"bucketId"`
		BucketName string `json:"bucketName"`
	} `json:"allowed"`
}

type b2ListBucketsResponse struct {
	Buckets []struct {
		BucketID   string `json:"bucketId"`
		BucketName string `json:"bucketName"`
	} `json:"buckets"`
}

type b2GetUploadURLResponse struct {
	BucketID           string `json:"bucketId"`
	UploadURL          string `json:"uploadUrl"`
	AuthorizationToken string `json:"authorizationToken"`
}

type b2ListFileNamesResponse struct {
	Files []struct {
		FileName string `json:"fileName"`
	} `json:"files"`
	NextFileName string `json:"nextFileName"`
}

type b2ListFileVersionsResponse struct {
	Files []struct {
		FileID   string `json:"fileId"`
		FileName string `json:"fileName"`
		Action   string `json:"action"`
	} `json:"files"`
	NextFileName string `json:"nextFileName"`
	NextFileID   string `json:"nextFileId"`
}

type b2ErrorResponse struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type B2NativeService struct {
	httpClient     *http.Client
	keyID          string
	applicationKey string
	bucketName     string

	mu        sync.Mutex
	accountID string
	bucketID  string
	authToken string
	apiURL    string
	download  string
}

func NewB2NativeService() (*B2NativeService, error) {
	keyID := strings.TrimSpace(os.Getenv("B2_KEY_ID"))
	applicationKey := strings.TrimSpace(os.Getenv("B2_APPLICATION_KEY"))
	bucketName := strings.TrimSpace(os.Getenv("B2_BUCKET_NAME"))

	if keyID == "" || applicationKey == "" {
		return nil, fmt.Errorf("B2_KEY_ID and B2_APPLICATION_KEY environment variables are required")
	}
	if bucketName == "" {
		return nil, fmt.Errorf("B2_BUCKET_NAME environment variable is required")
	}

	return &B2NativeService{
		httpClient:     &http.Client{Timeout: 60 * time.Second},
		keyID:          keyID,
		applicationKey: applicationKey,
		bucketName:     bucketName,
	}, nil
}

func (s *B2NativeService) GeneratePresignedUploadURL(key, contentType string) (string, error) {
	uploadURL, _, err := s.getUploadURL()
	if err != nil {
		return "", err
	}
	return uploadURL, nil
}

func (s *B2NativeService) GeneratePresignedDownloadURL(key string) (string, error) {
	if err := s.ensureAuthorized(); err != nil {
		return "", err
	}
	return s.downloadFileURL(key), nil
}

func (s *B2NativeService) GetPresignedUploadURL(key string, contentType string, expirationMinutes int) (string, error) {
	return s.GeneratePresignedUploadURL(key, contentType)
}

func (s *B2NativeService) GetPresignedDownloadURL(key string, expirationMinutes int) (string, error) {
	return s.GeneratePresignedDownloadURL(key)
}

func (s *B2NativeService) ObjectExists(key string) (bool, error) {
	if err := s.ensureAuthorized(); err != nil {
		return false, err
	}

	requestBody := map[string]interface{}{
		"bucketId":      s.bucketID,
		"startFileName": key,
		"maxFileCount":  1,
	}

	data, err := s.doAuthorizedJSONRequest("POST", s.apiURL+"/b2api/v2/b2_list_file_names", requestBody)
	if err != nil {
		return false, err
	}

	var response b2ListFileNamesResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return false, fmt.Errorf("failed to parse list file names response: %w", err)
	}

	if len(response.Files) == 0 {
		return false, nil
	}

	return response.Files[0].FileName == key, nil
}

func (s *B2NativeService) UploadObject(key string, content []byte, contentType string) error {
	return s.uploadObject(key, content, contentType)
}

func (s *B2NativeService) UploadEncryptedObject(key string, encryptedContent []byte, contentType string) error {
	return s.uploadObject(key, encryptedContent, contentType)
}

func (s *B2NativeService) DownloadObject(key string) ([]byte, error) {
	if err := s.ensureAuthorized(); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.TODO(), "GET", s.downloadFileURL(key), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build download request: %w", err)
	}
	if s.authToken != "" {
		req.Header.Set("Authorization", s.authToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download object: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download failed: %s", string(body))
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read downloaded content: %w", err)
	}

	return content, nil
}

func (s *B2NativeService) ComputeObjectHashAndSize(key string) (string, int64, error) {
	content, err := s.DownloadObject(key)
	if err != nil {
		return "", 0, err
	}

	hash := sha256.Sum256(content)
	return fmt.Sprintf("%x", hash[:]), int64(len(content)), nil
}

func (s *B2NativeService) DeleteObject(key string) error {
	if err := s.ensureAuthorized(); err != nil {
		return err
	}

	startFileName := key
	startFileID := ""
	deletedAny := false

	for {
		requestBody := map[string]interface{}{
			"bucketId":      s.bucketID,
			"startFileName": startFileName,
			"maxFileCount":  1000,
		}
		if startFileID != "" {
			requestBody["startFileId"] = startFileID
		}

		data, err := s.doAuthorizedJSONRequest("POST", s.apiURL+"/b2api/v2/b2_list_file_versions", requestBody)
		if err != nil {
			return err
		}

		var response b2ListFileVersionsResponse
		if err := json.Unmarshal(data, &response); err != nil {
			return fmt.Errorf("failed to parse list file versions response: %w", err)
		}

		for _, file := range response.Files {
			if file.FileName != key {
				return nil
			}

			deleteBody := map[string]string{
				"fileName": file.FileName,
				"fileId":   file.FileID,
			}

			if _, err := s.doAuthorizedJSONRequest("POST", s.apiURL+"/b2api/v2/b2_delete_file_version", deleteBody); err != nil {
				return err
			}
			deletedAny = true
		}

		if response.NextFileName == "" {
			break
		}

		startFileName = response.NextFileName
		startFileID = response.NextFileID
	}

	if !deletedAny {
		return nil
	}

	return nil
}

func (s *B2NativeService) GetBucketName() string {
	return s.bucketName
}

func (s *B2NativeService) uploadObject(key string, content []byte, contentType string) error {
	uploadURL, uploadToken, err := s.getUploadURL()
	if err != nil {
		return err
	}

	fileName := escapeB2FileName(key)
	sha := sha1.Sum(content)
	shaHex := fmt.Sprintf("%x", sha[:])

	req, err := http.NewRequestWithContext(context.TODO(), "POST", uploadURL, bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("failed to build upload request: %w", err)
	}

	req.Header.Set("Authorization", uploadToken)
	req.Header.Set("X-Bz-File-Name", fileName)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Bz-Content-Sha1", shaHex)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload object: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed: %s", string(body))
	}

	return nil
}

func (s *B2NativeService) getUploadURL() (string, string, error) {
	if err := s.ensureAuthorized(); err != nil {
		return "", "", err
	}

	requestBody := map[string]string{
		"bucketId": s.bucketID,
	}

	data, err := s.doAuthorizedJSONRequest("POST", s.apiURL+"/b2api/v2/b2_get_upload_url", requestBody)
	if err != nil {
		return "", "", err
	}

	var response b2GetUploadURLResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return "", "", fmt.Errorf("failed to parse upload url response: %w", err)
	}

	return response.UploadURL, response.AuthorizationToken, nil
}

func (s *B2NativeService) ensureAuthorized() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.authToken != "" && s.apiURL != "" && s.download != "" && s.bucketID != "" {
		return nil
	}

	return s.authorizeLocked()
}

func (s *B2NativeService) authorizeLocked() error {
	authURL := "https://api.backblazeb2.com/b2api/v2/b2_authorize_account"
	encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", s.keyID, s.applicationKey)))

	req, err := http.NewRequestWithContext(context.TODO(), "GET", authURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build authorize request: %w", err)
	}

	req.Header.Set("Authorization", "Basic "+encoded)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to authorize B2 account: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read authorize response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authorization failed: %s", string(body))
	}

	var response b2AuthorizeResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse authorize response: %w", err)
	}

	s.accountID = response.AccountID
	s.authToken = response.AuthorizationToken
	s.apiURL = response.APIURL
	s.download = response.DownloadURL

	if response.Allowed.BucketID != "" {
		s.bucketID = response.Allowed.BucketID
		if s.bucketName == "" && response.Allowed.BucketName != "" {
			s.bucketName = response.Allowed.BucketName
		}
	}

	if s.bucketID == "" {
		bucketID, err := s.resolveBucketIDLocked()
		if err != nil {
			return err
		}
		s.bucketID = bucketID
	}

	return nil
}

func (s *B2NativeService) resolveBucketIDLocked() (string, error) {
	requestBody := map[string]string{
		"accountId": s.accountID,
	}
	if s.bucketName != "" {
		requestBody["bucketName"] = s.bucketName
	}

	data, err := s.doAuthorizedJSONRequest("POST", s.apiURL+"/b2api/v2/b2_list_buckets", requestBody)
	if err != nil {
		return "", err
	}

	var response b2ListBucketsResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return "", fmt.Errorf("failed to parse list buckets response: %w", err)
	}

	for _, bucket := range response.Buckets {
		if bucket.BucketName == s.bucketName {
			return bucket.BucketID, nil
		}
	}

	return "", fmt.Errorf("bucket not found: %s", s.bucketName)
}

func (s *B2NativeService) doAuthorizedJSONRequest(method, url string, body interface{}) ([]byte, error) {
	payload := []byte{}
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to encode request body: %w", err)
		}
		payload = encoded
	}

	req, err := http.NewRequestWithContext(context.TODO(), method, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Set("Authorization", s.authToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		s.resetAuth()
		return s.retryAuthorizedRequest(method, url, body)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, s.parseB2Error(responseBody)
	}

	return responseBody, nil
}

func (s *B2NativeService) retryAuthorizedRequest(method, url string, body interface{}) ([]byte, error) {
	if err := s.ensureAuthorized(); err != nil {
		return nil, err
	}

	payload := []byte{}
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to encode retry body: %w", err)
		}
		payload = encoded
	}

	req, err := http.NewRequestWithContext(context.TODO(), method, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to build retry request: %w", err)
	}

	req.Header.Set("Authorization", s.authToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("retry request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read retry response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, s.parseB2Error(responseBody)
	}

	return responseBody, nil
}

func (s *B2NativeService) parseB2Error(body []byte) error {
	var b2Err b2ErrorResponse
	if err := json.Unmarshal(body, &b2Err); err == nil && b2Err.Message != "" {
		return fmt.Errorf("b2 error (%s): %s", b2Err.Code, b2Err.Message)
	}
	return fmt.Errorf("b2 request failed: %s", string(body))
}

func (s *B2NativeService) resetAuth() {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucketName
	s.accountID = ""
	s.bucketID = ""
	s.authToken = ""
	s.apiURL = ""
	s.download = ""
	s.bucketName = b
}

func (s *B2NativeService) downloadFileURL(key string) string {
	return fmt.Sprintf("%s/file/%s/%s", strings.TrimRight(s.download, "/"), s.bucketName, escapeB2FileName(key))
}

func escapeB2FileName(name string) string {
	escaped := url.PathEscape(name)
	return strings.ReplaceAll(escaped, "%2F", "/")
}
