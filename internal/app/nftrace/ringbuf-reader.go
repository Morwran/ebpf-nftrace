//go:build ringbuf
// +build ringbuf

package nftrace

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

//go:inline
func newReader(objs *ebpf.Map, buffLen int) (*ringbuf.Reader, error) {
	return ringbuf.NewReader(objs)
}

//go:inline
func newRecord() *ringbuf.Record {
	return new(ringbuf.Record)
}

//go:inline
func getLostSamples(rec *ringbuf.Record) uint64 {
	return 0
}
