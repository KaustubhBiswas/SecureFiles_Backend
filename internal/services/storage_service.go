package services

import (
	"fmt"
	"os"
	"strings"
)

type StorageProvider string

const (
	StorageProviderB2 StorageProvider = "b2"
)

type ObjectStorage interface {
	GeneratePresignedUploadURL(key, contentType string) (string, error)
	GeneratePresignedDownloadURL(key string) (string, error)
	GetPresignedUploadURL(key string, contentType string, expirationMinutes int) (string, error)
	GetPresignedDownloadURL(key string, expirationMinutes int) (string, error)
	ObjectExists(key string) (bool, error)
	UploadObject(key string, content []byte, contentType string) error
	UploadEncryptedObject(key string, encryptedContent []byte, contentType string) error
	DownloadObject(key string) ([]byte, error)
	ComputeObjectHashAndSize(key string) (string, int64, error)
	DeleteObject(key string) error
	GetBucketName() string
}

func NewStorageServiceFromEnv() (ObjectStorage, StorageProvider, error) {
	provider := normalizeStorageProvider(os.Getenv("STORAGE_PROVIDER"))
	if provider == "" {
		provider = StorageProviderB2
	}

	if provider != StorageProviderB2 {
		return nil, provider, fmt.Errorf("only the b2 storage provider is supported; set STORAGE_PROVIDER=b2")
	}

	primary, err := newStorageProvider(provider)
	if err != nil {
		return nil, provider, err
	}

	return primary, provider, nil
}

func newStorageProvider(provider StorageProvider) (ObjectStorage, error) {
	switch provider {
	case StorageProviderB2:
		return NewB2NativeService()
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", provider)
	}
}

func normalizeStorageProvider(value string) StorageProvider {
	return StorageProvider(strings.ToLower(strings.TrimSpace(value)))
}

type DualStorageService struct {
	primary  ObjectStorage
	fallback ObjectStorage
}

func NewDualStorageService(primary ObjectStorage, fallback ObjectStorage) ObjectStorage {
	return &DualStorageService{primary: primary, fallback: fallback}
}

func (d *DualStorageService) GeneratePresignedUploadURL(key, contentType string) (string, error) {
	return d.primary.GeneratePresignedUploadURL(key, contentType)
}

func (d *DualStorageService) GeneratePresignedDownloadURL(key string) (string, error) {
	return d.primary.GeneratePresignedDownloadURL(key)
}

func (d *DualStorageService) GetPresignedUploadURL(key string, contentType string, expirationMinutes int) (string, error) {
	return d.primary.GetPresignedUploadURL(key, contentType, expirationMinutes)
}

func (d *DualStorageService) GetPresignedDownloadURL(key string, expirationMinutes int) (string, error) {
	return d.primary.GetPresignedDownloadURL(key, expirationMinutes)
}

func (d *DualStorageService) ObjectExists(key string) (bool, error) {
	exists, err := d.primary.ObjectExists(key)
	if err == nil && exists {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return d.fallback.ObjectExists(key)
}

func (d *DualStorageService) UploadObject(key string, content []byte, contentType string) error {
	return d.primary.UploadObject(key, content, contentType)
}

func (d *DualStorageService) UploadEncryptedObject(key string, encryptedContent []byte, contentType string) error {
	return d.primary.UploadEncryptedObject(key, encryptedContent, contentType)
}

func (d *DualStorageService) DownloadObject(key string) ([]byte, error) {
	content, err := d.primary.DownloadObject(key)
	if err == nil {
		return content, nil
	}
	if !IsNotFoundError(err) {
		return nil, err
	}
	return d.fallback.DownloadObject(key)
}

func (d *DualStorageService) ComputeObjectHashAndSize(key string) (string, int64, error) {
	hash, size, err := d.primary.ComputeObjectHashAndSize(key)
	if err == nil {
		return hash, size, nil
	}
	if !IsNotFoundError(err) {
		return "", 0, err
	}
	return d.fallback.ComputeObjectHashAndSize(key)
}

func (d *DualStorageService) DeleteObject(key string) error {
	primaryErr := d.primary.DeleteObject(key)
	fallbackErr := d.fallback.DeleteObject(key)

	if primaryErr != nil && !IsNotFoundError(primaryErr) {
		if fallbackErr != nil && !IsNotFoundError(fallbackErr) {
			return fmt.Errorf("delete failed on primary and fallback: %v; %v", primaryErr, fallbackErr)
		}
		return primaryErr
	}

	if fallbackErr != nil && !IsNotFoundError(fallbackErr) {
		return fallbackErr
	}

	return nil
}

func (d *DualStorageService) GetBucketName() string {
	return d.primary.GetBucketName()
}
