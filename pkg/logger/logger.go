package logger

import (
	"fmt"
	"os"

	"go.uber.org/zap"
)

type Logger struct {
	*zap.SugaredLogger
}

func New(debug bool) *Logger {
	var logger *zap.Logger
	var err error
	if debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	return &Logger{logger.Sugar()}
}

func (l *Logger) Close() error {
	return l.Sync()
}
