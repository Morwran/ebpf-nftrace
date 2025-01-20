package nftrace

import (
	"flag"
	"os"
)

var (
	SampleRate        uint64
	LogLevel          string
	RingBuffSize      int
	TimeInterval      uint64
	Mode              string
	TelemetryEndpoint string
	EvRate            uint64
)

func init() {
	flag.Uint64Var(&SampleRate, "rate", 0, "sample rate value for the tracing")
	flag.IntVar(&RingBuffSize, "size", os.Getpagesize(), "receive ring buffer size in bytes")
	flag.StringVar(&LogLevel, "level", "INFO", "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL")
	flag.Uint64Var(&TimeInterval, "ti", 0, "agregation time interval in nano sec")
	flag.StringVar(&Mode, "m", "push", "push|pull mode")
	flag.StringVar(&TelemetryEndpoint, "tl", "0.0.0.0:5000", "telemetry endpoint addr")
	flag.Uint64Var(&EvRate, "ev", 10, "produce events per second: 1...100")
	flag.Parse()
}
