package printer

import (
	"fmt"

	model "github.com/Morwran/ebpf-nftrace/internal/models"

	"github.com/H-BF/corlib/logger"
	linq "github.com/ahmetb/go-linq/v3"
	"go.uber.org/zap"
)

type Option func(*printerImpl)

func WithLogger(log logger.TypeOfLogger) Option {
	return func(p *printerImpl) {
		p.log = log
	}
}

func WithJsonFormat() Option {
	return func(p *printerImpl) {
		p.jsonFormat = true
	}
}

type TracePrinter interface {
	Print(...model.Trace)
}

type (
	PrinterF    func(msg string, keysAndValues ...interface{})
	printerImpl struct {
		log        logger.TypeOfLogger
		jsonFormat bool
	}
	dummyPrinter struct{}
)

func NewTracePrinter(options ...Option) TracePrinter {
	p := &printerImpl{
		log: logger.New(zap.InfoLevel),
	}
	for _, opt := range options {
		opt(p)
	}
	return p
}

func (p printerImpl) Print(traces ...model.Trace) {
	print := p.log.Infow
	if !p.jsonFormat {
		print = p.log.Infof
	}
	PrintTrace(traces, p.jsonFormat, false, print, nil)
}

func NewDummyPrinter() TracePrinter {
	return &dummyPrinter{}
}

func (p dummyPrinter) Print(traces ...model.Trace) {
}

func PrintTrace(traces []model.Trace, jsonFormat, printTimestamp bool, print PrinterF, callback func(trace model.Trace)) {
	cntUniqueTrace := make(map[string]uint64, len(traces))
	uniqueTrace := make(map[string]model.Trace, len(traces))

	for _, trace := range traces {
		key := trace.FiveTuple()
		if jsonFormat {
			key = trace.JsonString()
		}
		cntUniqueTrace[key]++
		if _, ok := uniqueTrace[key]; !ok {
			uniqueTrace[key] = trace
		}
	}
	linq.From(uniqueTrace).ForEach(func(i any) {
		kv := i.(linq.KeyValue)
		key := kv.Key.(string)
		val := kv.Value.(model.Trace)
		if !jsonFormat {
			timestamp := ""
			if printTimestamp {
				timestamp = fmt.Sprintf("[%s] ", val.Timestamp)
			}
			print("%s%s cnt=%d\n", timestamp, key, val.Cnt*cntUniqueTrace[key])
		} else {
			print("", "trace", val, "cnt", cntUniqueTrace[key])
		}
		if callback != nil {
			callback(val)
		}
	})
}
