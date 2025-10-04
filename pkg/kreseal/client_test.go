package kreseal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/eeekcct/kreseal/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	cert := createTestCert(t)
	client := NewClient(log, cert)
	assert.NotNil(t, client)
	assert.NotNil(t, client.Logger)
	assert.NotNil(t, client.Cert)
	assert.Equal(t, cert, client.Cert)
}

func TestClient_UnsealSealedSecret_Errors(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	tests := []struct {
		name          string
		setupFunc     func(t *testing.T) (inputFile, outputFile string, client *Client)
		expectedError string
	}{
		{
			name: "file not found",
			setupFunc: func(t *testing.T) (string, string, *Client) {
				return "nonexistent.yaml", "output.yaml", NewClient(log, createTestCert(t))
			},
			expectedError: "failed to read input file",
		},
		{
			name: "no cert",
			setupFunc: func(t *testing.T) (string, string, *Client) {
				testSealedSecret := `---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-secret
  namespace: default
spec:
  encryptedData:
    username: dGVzdA==
  template:
    metadata:
      name: test-secret
    type: Opaque`
				tmpDir := t.TempDir()
				inputFile := filepath.Join(tmpDir, "sealedsecret.yaml")
				outputFile := filepath.Join(tmpDir, "secret.yaml")
				err := os.WriteFile(inputFile, []byte(testSealedSecret), 0644)
				require.NoError(t, err)
				return inputFile, outputFile, NewClient(log, createTestCert(t))
			},
			expectedError: "", // nil pointer error
		},
		{
			name: "no sealed secrets",
			setupFunc: func(t *testing.T) (string, string, *Client) {
				testData := `---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm`
				tmpDir := t.TempDir()
				inputFile := filepath.Join(tmpDir, "invalid.yaml")
				outputFile := filepath.Join(tmpDir, "secret.yaml")
				err := os.WriteFile(inputFile, []byte(testData), 0644)
				require.NoError(t, err)
				return inputFile, outputFile, NewClient(log, createTestCert(t))
			},
			expectedError: "no SealedSecrets found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputFile, outputFile, client := tt.setupFunc(t)
			err := client.UnsealSealedSecret(inputFile, outputFile)
			assert.Error(t, err)
			if tt.expectedError != "" {
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

func TestClient_ResealSecret_Errors(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	tests := []struct {
		name          string
		setupFunc     func(t *testing.T) (inputFile, outputFile string, client *Client)
		expectedError string
		checkRestore  bool
	}{
		{
			name: "output file not found (no backup)",
			setupFunc: func(t *testing.T) (string, string, *Client) {
				tmpDir := t.TempDir()
				return filepath.Join(tmpDir, "secret.yaml"), filepath.Join(tmpDir, "sealed.yaml"), NewClient(log, createTestCert(t))
			},
			expectedError: "failed to create backup",
		},
		{
			name: "input file not found",
			setupFunc: func(t *testing.T) (string, string, *Client) {
				return "nonexistent.yaml", "output.yaml", NewClient(log, createTestCert(t))
			},
			expectedError: "failed to create backup",
		},
		{
			name: "no secrets in input",
			setupFunc: func(t *testing.T) (string, string, *Client) {
				testData := `---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm`
				tmpDir := t.TempDir()
				inputFile := filepath.Join(tmpDir, "invalid.yaml")
				outputFile := filepath.Join(tmpDir, "sealed.yaml")
				err := os.WriteFile(inputFile, []byte(testData), 0644)
				require.NoError(t, err)
				err = os.WriteFile(outputFile, []byte("original content"), 0644)
				require.NoError(t, err)
				return inputFile, outputFile, NewClient(log, createTestCert(t))
			},
			expectedError: "no Secrets found",
			checkRestore:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputFile, outputFile, client := tt.setupFunc(t)

			// Save original content if checking restore
			var originalContent []byte
			if tt.checkRestore {
				originalContent, _ = os.ReadFile(outputFile)
			}

			err := client.ResealSecret(inputFile, outputFile)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)

			// Verify backup was restored
			if tt.checkRestore {
				content, err := os.ReadFile(outputFile)
				require.NoError(t, err)
				assert.Equal(t, originalContent, content)
			}
		})
	}
}

func TestClient_EditFile_InvalidEditor(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log, createTestCert(t))

	testFile := filepath.Join(t.TempDir(), "test.yaml")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	originalEditor := os.Getenv("EDITOR")
	defer os.Setenv("EDITOR", originalEditor)
	os.Setenv("EDITOR", "nonexistent-editor-12345")

	err = client.EditFile(testFile)
	assert.Error(t, err)
}

func TestClient_EditFile_Success(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log, createTestCert(t))

	testFile := filepath.Join(t.TempDir(), "test.yaml")

	// Set EDITOR to a simple command that exits successfully on all platforms
	if os.Getenv("OS") == "Windows_NT" {
		t.Setenv("EDITOR", "powershell -NoProfile -Command echo")
	} else {
		t.Setenv("EDITOR", "echo")
	}

	// EditFile should successfully execute the editor command
	err := client.EditFile(testFile)
	assert.NoError(t, err)
}

func TestClient_HelperFunctions(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log, createTestCert(t))

	t.Run("marshalYAML", func(t *testing.T) {
		data := map[string]string{"key": "value"}
		var buf bytes.Buffer
		err := client.marshalYAML(data, &buf)
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "---")
		assert.Contains(t, buf.String(), "key: value")
	})

	t.Run("writeYAML success", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString("test: data\n")
		outputFile := filepath.Join(t.TempDir(), "output.yaml")
		err := client.writeYAML(&buf, outputFile)
		assert.NoError(t, err)
		content, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		assert.Equal(t, "test: data\n", string(content))
	})

	t.Run("writeYAML invalid path", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString("test: data\n")
		err := client.writeYAML(&buf, "/invalid/path/that/does/not/exist/file.yaml")
		assert.Error(t, err)
	})
}

func TestClient_ResealSecret_Success(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	// Create a test certificate
	cert := createTestCert(t)

	// Valid Secret YAML
	testSecret := `---
apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  namespace: default
type: Opaque
data:
  username: dXNlcm5hbWU=
  password: cGFzc3dvcmQ=`

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "secret.yaml")
	outputFile := filepath.Join(tmpDir, "sealed.yaml")

	// Create input file
	err := os.WriteFile(inputFile, []byte(testSecret), 0644)
	require.NoError(t, err)

	// Create output file (to be backed up)
	err = os.WriteFile(outputFile, []byte("old sealed secret"), 0644)
	require.NoError(t, err)

	client := NewClient(log, createTestCert(t))
	client.Cert = cert

	// Reseal should succeed
	err = client.ResealSecret(inputFile, outputFile)
	assert.NoError(t, err)

	// Verify output file was created and contains SealedSecret
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "kind: SealedSecret")
	assert.Contains(t, string(content), "encryptedData:")

	// Verify backup was removed
	backupFile := outputFile + ".bak"
	_, err = os.Stat(backupFile)
	assert.True(t, os.IsNotExist(err), "backup file should be removed on success")
}

func TestClient_UnsealSealedSecret_Success(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	cert := createTestCert(t)

	// Encrypt some test data
	testData := []byte("secret-value")
	label := []byte("default/test-secret")
	encryptedValue, err := cert.Encrypt(testData, label)
	require.NoError(t, err)

	// Create SealedSecret with encrypted data
	testSealedSecret := `---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: test-secret
  namespace: default
spec:
  encryptedData:
    password: ` + encryptedValue + `
  template:
    metadata:
      name: test-secret
    type: Opaque`

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "sealedsecret.yaml")
	outputFile := filepath.Join(tmpDir, "secret.yaml")

	err = os.WriteFile(inputFile, []byte(testSealedSecret), 0644)
	require.NoError(t, err)

	client := NewClient(log, createTestCert(t))
	client.Cert = cert

	// Unseal should succeed
	err = client.UnsealSealedSecret(inputFile, outputFile)
	assert.NoError(t, err)

	// Verify output file contains Secret
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "kind: Secret")
	assert.Contains(t, string(content), "password:")
}
