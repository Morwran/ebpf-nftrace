package nftrace

import (
	"flag"
	"os"
)

var (
	SampleRate   uint64
	LogLevel     string
	RingBuffSize int
)

func init() {
	flag.Uint64Var(&SampleRate, "rate", 0, "sample rate value for the tracing")
	flag.IntVar(&RingBuffSize, "size", os.Getpagesize(), "receive ring buffer size in bytes")
	flag.StringVar(&LogLevel, "level", "INFO", "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL")
	flag.Parse()
}
