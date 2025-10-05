package kreseal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// Test helper functions to reduce code duplication

// generateTestCert creates a test RSA key pair and certificate
func generateTestCert(t *testing.T) (*rsa.PrivateKey, []byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return privateKey, privKeyPEM, certPEM
}

// generateECDSACert generates an ECDSA certificate for testing non-RSA key rejection
func generateECDSACert(t *testing.T) []byte {
	t.Helper()

	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ecdsa-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	// Create certificate with ECDSA public key
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}

// createTestCert creates a Cert instance with test keys
func createTestCert(t *testing.T) *Cert {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return &Cert{
		PublicKey:       &privateKey.PublicKey,
		PrivateKey:      privateKey,
		SessionKeyBytes: 32,
	}
}

func TestCert_EncryptDecrypt(t *testing.T) {
	cert := createTestCert(t)
	data := []byte("test secret data")
	label := []byte("default/my-secret")

	// Encrypt
	encrypted, err := cert.Encrypt(data, label)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, string(data), encrypted)

	// Decrypt
	decrypted, err := cert.Decrypt(encrypted, label)
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCert_Decrypt_InvalidData(t *testing.T) {
	cert := createTestCert(t)

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

func TestCert_Decrypt_WrongLabel(t *testing.T) {
	cert := createTestCert(t)

	data := []byte("test secret data")
	label1 := []byte("default/secret1")
	label2 := []byte("default/secret2")

	// Encrypt with label1
	encrypted, err := cert.Encrypt(data, label1)
	require.NoError(t, err)

	// Decrypt with wrong label should fail
	_, err = cert.Decrypt(encrypted, label2)
	assert.Error(t, err)
}

func TestNewCert_InvalidSecret(t *testing.T) {
	cert, err := NewCert("non-existent-secret", "default")
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestNewCert_KubeconfigError(t *testing.T) {
	// Save original environment
	originalKubeconfig := os.Getenv("KUBECONFIG")
	originalHome := os.Getenv("HOME")
	originalUserProfile := os.Getenv("USERPROFILE")

	defer func() {
		// Restore environment
		if originalKubeconfig != "" {
			_ = os.Setenv("KUBECONFIG", originalKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		}
		if originalUserProfile != "" {
			_ = os.Setenv("USERPROFILE", originalUserProfile)
		}
	}()

	// Set kubeconfig to non-existent path
	_ = os.Setenv("KUBECONFIG", "/nonexistent/invalid/kubeconfig.yaml")
	// Also clear HOME to prevent fallback to ~/.kube/config
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("USERPROFILE")

	cert, err := NewCert("test-secret", "default")

	// This should fail because kubeconfig is invalid
	// However, the error behavior depends on the k8s client implementation
	// In some cases it may still try to use in-cluster config
	if err != nil {
		assert.Error(t, err)
		assert.Nil(t, cert)
	} else {
		// If it didn't error (e.g., found in-cluster config), skip this test
		t.Skip("k8s.NewClient succeeded despite invalid kubeconfig (possibly using in-cluster config)")
	}
}

func Test_parsePrivateKey(t *testing.T) {
	privateKey, privKeyPEM, _ := generateTestCert(t)

	// Test parsing
	parsedKey, err := parsePrivateKey(privKeyPEM)
	assert.NoError(t, err)
	assert.NotNil(t, parsedKey)
	assert.Equal(t, privateKey.N, parsedKey.N)
}

func Test_parsePrivateKey_InvalidPEM(t *testing.T) {
	_, _, certPEM := generateTestCert(t)

	tests := []struct {
		name    string
		pemData []byte
	}{
		{
			name:    "not PEM format",
			pemData: []byte("this is not a PEM format"),
		},
		{
			name:    "wrong PEM type - certificate instead of private key",
			pemData: certPEM,
		},
		{
			name:    "empty data",
			pemData: []byte(""),
		},
		{
			name: "invalid key data",
			pemData: []byte(`-----BEGIN RSA PRIVATE KEY-----
aW52YWxpZCBrZXkgZGF0YQ==
-----END RSA PRIVATE KEY-----`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePrivateKey(tt.pemData)
			assert.Error(t, err)
		})
	}
}

func Test_parsePublicKey(t *testing.T) {
	privateKey, _, certPEM := generateTestCert(t)

	// Test parsing
	parsedKey, err := parsePublicKey(certPEM)
	assert.NoError(t, err)
	assert.NotNil(t, parsedKey)
	assert.Equal(t, privateKey.Public().(*rsa.PublicKey).N, parsedKey.N)
}

func Test_parsePublicKey_InvalidPEM(t *testing.T) {
	_, privKeyPEM, _ := generateTestCert(t)
	ecdsaCertPEM := generateECDSACert(t)

	tests := []struct {
		name          string
		pemData       []byte
		expectedError string
	}{
		{
			name:          "not PEM format",
			pemData:       []byte("this is not a PEM format"),
			expectedError: "failed to decode PEM block",
		},
		{
			name:          "wrong PEM type - private key instead of certificate",
			pemData:       privKeyPEM,
			expectedError: "failed to decode PEM block",
		},
		{
			name:          "empty data",
			pemData:       []byte(""),
			expectedError: "failed to decode PEM block",
		},
		{
			name: "invalid certificate data",
			pemData: []byte(`-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----`),
			expectedError: "failed to parse certificate",
		},
		{
			name:          "non-RSA certificate (ECDSA)",
			pemData:       ecdsaCertPEM,
			expectedError: "public key is not of type RSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePublicKey(tt.pemData)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// mockSecretClient is a mock implementation of k8s.ClientInterface for testing
type mockSecretClient struct {
	secret *corev1.Secret
	err    error
}

func (m *mockSecretClient) GetSecret(name, namespace string) (*corev1.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.secret, nil
}

func Test_getCertFromClient_Success(t *testing.T) {
	privateKey, privKeyPEM, certPEM := generateTestCert(t)

	// Create mock secret
	mockSecret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.key": privKeyPEM,
			"tls.crt": certPEM,
		},
	}

	mockClient := &mockSecretClient{secret: mockSecret}

	// Test getCertFromClient
	pubKey, privKey, err := getCertFromClient(mockClient, "test-secret", "default")
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.NotNil(t, privKey)
	assert.Equal(t, privateKey.Public().(*rsa.PublicKey).N, pubKey.N)
	assert.Equal(t, privateKey.N, privKey.N)
}

func Test_getCertFromClient_Errors(t *testing.T) {
	_, privKeyPEM, _ := generateTestCert(t)

	tests := []struct {
		name          string
		client        *mockSecretClient
		expectedError string
	}{
		{
			name: "secret not found",
			client: &mockSecretClient{
				err: fmt.Errorf("secret not found"),
			},
			expectedError: "secret not found",
		},
		{
			name: "invalid private key",
			client: &mockSecretClient{
				secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.key": []byte("invalid private key"),
						"tls.crt": []byte("valid cert would go here"),
					},
				},
			},
			expectedError: "failed to decode PEM block",
		},
		{
			name: "invalid certificate",
			client: &mockSecretClient{
				secret: &corev1.Secret{
					Data: map[string][]byte{
						"tls.key": privKeyPEM,
						"tls.crt": []byte("invalid certificate"),
					},
				},
			},
			expectedError: "failed to decode PEM block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := getCertFromClient(tt.client, "test-secret", "default")
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestNewCertWithClient_Success(t *testing.T) {
	privateKey, privKeyPEM, certPEM := generateTestCert(t)

	// Create mock secret
	mockSecret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.key": privKeyPEM,
			"tls.crt": certPEM,
		},
	}

	mockClient := &mockSecretClient{secret: mockSecret}

	// Test NewCertWithClient
	cert, err := NewCertWithClient(mockClient, "test-secret", "default")
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, cert.PublicKey)
	assert.NotNil(t, cert.PrivateKey)
	assert.Equal(t, 32, cert.SessionKeyBytes)
	assert.Equal(t, privateKey.Public().(*rsa.PublicKey).N, cert.PublicKey.N)
	assert.Equal(t, privateKey.N, cert.PrivateKey.N)
}

func TestNewCertWithClient_Error(t *testing.T) {
	mockClient := &mockSecretClient{
		err: fmt.Errorf("secret not found"),
	}

	cert, err := NewCertWithClient(mockClient, "test-secret", "default")
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "secret not found")
}
