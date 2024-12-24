package nftrace

import (
	"github.com/H-BF/corlib/logger"
	"go.uber.org/zap/zapcore"
)

// SetupLogger setup app logger
func SetupLogger(l zapcore.Level) error {
	logger.SetLevel(l)
	return nil
}
