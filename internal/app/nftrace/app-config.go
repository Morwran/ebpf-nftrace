package nftrace

import "flag"

var (
	SampleRate uint64
	MapType    string
	LogLevel   string
)

func init() {
	flag.Uint64Var(&SampleRate, "rate", 0, "sample rate value for the tracing")
	flag.StringVar(&MapType, "map", "ring", "map type for transmitting traces from kernel (ring or perf)")
	flag.StringVar(&LogLevel, "level", "INFO", "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL")
	flag.Parse()
}
