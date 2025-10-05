package kreseal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eeekcct/kreseal/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTempFile_CreateTempFile(t *testing.T) {
	log := logger.New(false)
	defer func() { _ = log.Close() }()

	tempFile := NewTempFile(log)
	require.NotNil(t, tempFile)

	// Create temp file from original file
	originalFile := "testfile.yaml"

	err := tempFile.CreateTempFile(originalFile)
	require.NoError(t, err)
	defer tempFile.Cleanup()

	// Verify temp file exists
	_, err = os.Stat(tempFile.Path)
	assert.NoError(t, err)

	// Verify extension
	assert.Equal(t, ".yaml", filepath.Ext(tempFile.Path))

	// Verify path is not empty
	assert.NotEmpty(t, tempFile.Path)
}

func TestTempFile_Cleanup(t *testing.T) {
	log := logger.New(false)
	defer func() { _ = log.Close() }()

	tempFile := NewTempFile(log)

	// Create a temporary file
	originalFile := "testfile.yaml"

	err := tempFile.CreateTempFile(originalFile)
	require.NoError(t, err)

	tempPath := tempFile.Path

	// Verify file exists
	_, err = os.Stat(tempPath)
	require.NoError(t, err)

	// Cleanup
	tempFile.Cleanup()

	// Verify file is deleted
	_, err = os.Stat(tempPath)
	assert.True(t, os.IsNotExist(err))
}

func TestTempFile_Cleanup_NonExistent(t *testing.T) {
	log := logger.New(false)
	defer func() { _ = log.Close() }()

	tempFile := NewTempFile(log)
	tempFile.Path = "/tmp/non-existent-file-12345.yaml"

	// Should not panic or error
	tempFile.Cleanup()
}
