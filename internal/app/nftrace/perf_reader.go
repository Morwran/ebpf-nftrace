//go:build perf
// +build perf

package nftrace

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

//go:inline
func newReader(objs *ebpf.Map, buffLen int) (*perf.Reader, error) {
	return perf.NewReader(objs, buffLen)
}

//go:inline
func newRecord() *perf.Record {
	return new(perf.Record)
}

//go:inline
func getLostSamples(rec *perf.Record) uint64 {
	return rec.LostSamples
}
