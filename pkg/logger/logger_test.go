package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	logger := New(false)
	assert.NotNil(t, logger)
}

func TestLogger_Debugf(t *testing.T) {
	t.Run("debug mode enabled", func(t *testing.T) {
		logger := New(true)
		// Debug messages should be logged
		// Note: In actual implementation, you'd need to capture output
		logger.Debugf("test debug: %s", "value")
	})

	t.Run("debug mode disabled", func(t *testing.T) {
		logger := New(false)
		// Debug messages should not be logged
		logger.Debugf("test debug: %s", "value")
	})
}

func TestLogger_Infof(t *testing.T) {
	logger := New(false)
	logger.Infof("test info: %s", "value")
	// Info messages should always be logged
}

func TestLogger_Warnf(t *testing.T) {
	logger := New(false)
	logger.Warnf("test warning: %s", "value")
	// Warning messages should always be logged
}

func TestLogger_Errorf(t *testing.T) {
	logger := New(false)
	logger.Errorf("test error: %s", "value")
	// Error messages should always be logged
}

func TestLogger_Close(t *testing.T) {
	logger := New(false)
	logger.Close()
	// Close doesn't return an error, just ensure it doesn't panic
	assert.NotNil(t, logger)
}
