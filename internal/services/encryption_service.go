package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

type EncryptionService struct {
	key []byte
}

func NewEncryptionService(masterKey string) *EncryptionService {
	// Derive a 32-byte key from master key using SHA-256
	hash := sha256.Sum256([]byte(masterKey))
	return &EncryptionService{
		key: hash[:],
	}
}

// EncryptFile encrypts file content using AES-GCM
func (e *EncryptionService) EncryptFile(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptFile decrypts file content using AES-GCM
func (e *EncryptionService) DecryptFile(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptStream encrypts data from reader and writes to writer
func (e *EncryptionService) EncryptStream(plainReader io.Reader, cipherWriter io.Writer) error {
	// Read all data (for simplicity - could be optimized for streaming)
	plaintext, err := io.ReadAll(plainReader)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %w", err)
	}

	// Encrypt
	ciphertext, err := e.EncryptFile(plaintext)
	if err != nil {
		return err
	}

	// Write encrypted data
	_, err = cipherWriter.Write(ciphertext)
	return err
}

// DecryptStream decrypts data from reader and writes to writer
func (e *EncryptionService) DecryptStream(cipherReader io.Reader, plainWriter io.Writer) error {
	// Read all encrypted data
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		return fmt.Errorf("failed to read ciphertext: %w", err)
	}

	// Decrypt
	plaintext, err := e.DecryptFile(ciphertext)
	if err != nil {
		return err
	}

	// Write decrypted data
	_, err = plainWriter.Write(plaintext)
	return err
}

// GenerateFileKey generates a unique encryption key for a file
func (e *EncryptionService) GenerateFileKey(userID, fileID string) []byte {
	// Combine master key with user ID and file ID
	combined := fmt.Sprintf("%s:%s:%s", string(e.key), userID, fileID)
	hash := sha256.Sum256([]byte(combined))
	return hash[:]
}
