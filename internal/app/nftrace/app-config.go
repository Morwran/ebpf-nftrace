package nftrace

import (
	"flag"
)

var (
	SampleRate        uint64
	LogLevel          string
	RingBuffSize      int
	TelemetryEndpoint string
	EvRate            uint64
	CollectorType     string
	UseAggregation    bool
	JsonFormat        bool
	NoPrintTrace      bool
)

func init() {
	flag.Uint64Var(&SampleRate, "rate", 0, "sample rate value for the tracing")
	flag.IntVar(&RingBuffSize, "size", 16777216, "receive ring buffer size in bytes")
	flag.StringVar(&LogLevel, "level", "INFO", "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL")
	flag.StringVar(&TelemetryEndpoint, "tl", "0.0.0.0:5000", "telemetry endpoint addr")
	flag.Uint64Var(&EvRate, "ev", 10, "produce events per second: 1...100")
	flag.StringVar(&CollectorType, "c", "ebpf", "type of collector: ebpf|netlink")
	flag.BoolVar(&UseAggregation, "a", false, "use aggregation")
	flag.BoolVar(&JsonFormat, "j", false, "print in json format")
	flag.BoolVar(&NoPrintTrace, "np", false, "don't print trace (e.g. for debugging reasons)")
	flag.Parse()
}
