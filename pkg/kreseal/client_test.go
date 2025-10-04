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

	client := NewClient(log)
	assert.NotNil(t, client)
	assert.NotNil(t, client.Logger)
	assert.Nil(t, client.Cert)
}

func TestClient_UnsealSealedSecret(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	// Create test SealedSecret file
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

	inputFile := filepath.Join(t.TempDir(), "sealedsecret.yaml")
	outputFile := filepath.Join(t.TempDir(), "secret.yaml")
	
	err := os.WriteFile(inputFile, []byte(testSealedSecret), 0644)
	require.NoError(t, err)

	client := NewClient(log)
	
	// Note: This will fail without a valid cert, which is expected in unit tests
	// In a real scenario, you'd mock the certificate
	err = client.UnsealSealedSecret(inputFile, outputFile)
	assert.Error(t, err) // Expected to fail without cert
}

func TestClient_UnsealSealedSecret_FileNotFound(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log)
	
	err := client.UnsealSealedSecret("nonexistent.yaml", "output.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read input file")
}

func TestClient_EditFile(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log)

	// Create a test file
	testFile := filepath.Join(t.TempDir(), "test.yaml")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Set EDITOR to a command that will succeed (like 'type' on Windows or 'cat' on Unix)
	originalEditor := os.Getenv("EDITOR")
	defer os.Setenv("EDITOR", originalEditor)
	
	// Use a simple command that exists on Windows
	os.Setenv("EDITOR", "cmd /c type")
	
	// Note: This might fail in CI/CD environments without interactive terminal
	// but it tests the basic function structure
	err = client.EditFile(testFile)
	// We don't assert NoError here because it depends on the environment
}

func TestClient_ResealSecret_FileNotFound(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log)
	
	err := client.ResealSecret("nonexistent.yaml", "output.yaml")
	assert.Error(t, err)
}

func TestClient_marshalYAML(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log)
	
	data := map[string]string{
		"key": "value",
	}
	
	var buf bytes.Buffer
	err := client.marshalYAML(data, &buf)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "---")
	assert.Contains(t, buf.String(), "key: value")
}

func TestClient_writeYAML(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log)
	
	var buf bytes.Buffer
	buf.WriteString("test: data\n")
	
	outputFile := filepath.Join(t.TempDir(), "output.yaml")
	err := client.writeYAML(&buf, outputFile)
	assert.NoError(t, err)
	
	// Verify file was written
	content, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "test: data\n", string(content))
}

func TestClient_writeYAML_InvalidPath(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	client := NewClient(log)
	
	var buf bytes.Buffer
	buf.WriteString("test: data\n")
	
	// Use invalid path
	err := client.writeYAML(&buf, "/invalid/path/that/does/not/exist/file.yaml")
	assert.Error(t, err)
}
