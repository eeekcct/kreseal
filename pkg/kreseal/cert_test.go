package kreseal

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCert_Encrypt(t *testing.T) {
	// Generate test keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &Cert{
		PublicKey:       &privateKey.PublicKey,
		PrivateKey:      privateKey,
		SessionKeyBytes: 32,
	}

	data := []byte("test secret data")
	label := []byte("default/my-secret")

	encrypted, err := cert.Encrypt(data, label)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, string(data), encrypted)
}

func TestCert_Decrypt(t *testing.T) {
	// Generate test keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &Cert{
		PublicKey:       &privateKey.PublicKey,
		PrivateKey:      privateKey,
		SessionKeyBytes: 32,
	}

	data := []byte("test secret data")
	label := []byte("default/my-secret")

	// Encrypt
	encrypted, err := cert.Encrypt(data, label)
	require.NoError(t, err)

	// Decrypt
	decrypted, err := cert.Decrypt(encrypted, label)
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCert_Decrypt_InvalidData(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &Cert{
		PublicKey:       &privateKey.PublicKey,
		PrivateKey:      privateKey,
		SessionKeyBytes: 32,
	}

	tests := []struct {
		name          string
		encryptedData string
	}{
		{
			name:          "invalid base64",
			encryptedData: "not-valid-base64!!!",
		},
		{
			name:          "empty string",
			encryptedData: "",
		},
		{
			name:          "too short data",
			encryptedData: "QWc=", // "Ag" in base64, too short
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cert.Decrypt(tt.encryptedData, []byte("label"))
			assert.Error(t, err)
		})
	}
}

func TestCert_EncryptDecrypt_DifferentLabels(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &Cert{
		PublicKey:       &privateKey.PublicKey,
		PrivateKey:      privateKey,
		SessionKeyBytes: 32,
	}

	data := []byte("test secret data")
	label1 := []byte("default/secret1")
	label2 := []byte("default/secret2")

	// Encrypt with label1
	encrypted, err := cert.Encrypt(data, label1)
	require.NoError(t, err)

	// Decrypt with wrong label should fail
	_, err = cert.Decrypt(encrypted, label2)
	assert.Error(t, err)

	// Decrypt with correct label should succeed
	decrypted, err := cert.Decrypt(encrypted, label1)
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCert_Decrypt_ShortData(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &Cert{
		PublicKey:       &privateKey.PublicKey,
		PrivateKey:      privateKey,
		SessionKeyBytes: 32,
	}

	// Create data that's too short (less than 2 bytes)
	shortData := base64.StdEncoding.EncodeToString([]byte{0x00})
	
	_, err = cert.Decrypt(shortData, []byte("label"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid encrypted data length")
}

func TestCert_Encrypt_EmptyData(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &Cert{
		PublicKey:       &privateKey.PublicKey,
		PrivateKey:      privateKey,
		SessionKeyBytes: 32,
	}

	// Encrypt empty data
	encrypted, err := cert.Encrypt([]byte{}, []byte("label"))
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// Decrypt should work
	decrypted, err := cert.Decrypt(encrypted, []byte("label"))
	assert.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestNewCert_InvalidSecret(t *testing.T) {
	// This will fail because the secret doesn't exist
	cert, err := NewCert("non-existent-secret", "default")
	assert.Error(t, err)
	assert.Nil(t, cert)
}
