//go:build ringbuf
// +build ringbuf

package nftrace

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func newReader(objs *ebpf.Map) (*ringbuf.Reader, error) {
	return ringbuf.NewReader(objs)
}
