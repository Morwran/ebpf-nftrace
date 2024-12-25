package nftrace

import (
	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
)

// SetupLogger setup app logger
func SetupLogger(lvl string) error {
	var l logger.LogLevel
	if e := l.UnmarshalText([]byte(lvl)); e != nil {
		return errors.Wrapf(e, "recognize '%s' logger level from config", lvl)
	}
	logger.SetLevel(l)
	return nil
}
