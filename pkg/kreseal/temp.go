package kreseal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/eeekcct/kreseal/pkg/logger"
)

// TempFile represents a temporary file with automatic cleanup
type TempFile struct {
	Path   string
	logger *logger.Logger
}

// New creates a new TempFile instance without creating the actual file
func NewTempFile(logger *logger.Logger) *TempFile {
	return &TempFile{
		logger: logger,
	}
}

// CreateTempFile creates a unique temporary file based on the original file name
func (tf *TempFile) CreateTempFile(originalFile string) error {
	fileName := filepath.Base(originalFile)
	ext := filepath.Ext(fileName)
	nameWithoutExt := fileName[:len(fileName)-len(ext)]

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("%s-*%s", nameWithoutExt, ext))
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	tf.Path = tmpFile.Name()
	tf.logger.Debugf("Created temporary file: %s", tf.Path)

	return nil
}

// Cleanup removes the temporary file
func (tf *TempFile) Cleanup() {
	if err := os.Remove(tf.Path); err != nil {
		tf.logger.Warnf("Failed to remove temporary file %s: %v", tf.Path, err)
	} else {
		tf.logger.Debugf("Temporary file removed: %s", tf.Path)
	}
}
