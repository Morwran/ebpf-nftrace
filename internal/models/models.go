package models

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/cespare/xxhash"
)

type (
	// Trace -
	Trace struct {
		// trace id
		TrId uint32 `json:"trace_id"`
		// nftables table name
		Table string `json:"table_name"`
		// nftables chain name
		Chain string `json:"chain_name"`
		// nftables jump to a target name
		JumpTarget string `json:"jt,omitempty"`
		// nftables rule number
		RuleHandle uint64 `json:"handle"`
		// protocols family
		Family string `json:"family"`
		// input network interface
		Iifname string `json:"iif,omitempty"`
		// output network interface
		Oifname string `json:"oif,omitempty"`
		// source mac address
		SMacAddr string `json:"hw-src,omitempty"`
		// destination mac address
		DMacAddr string `json:"hw-dst,omitempty"`
		// source ip address
		SAddr string `json:"ip-src,omitempty"`
		// destination ip address
		DAddr string `json:"ip-dst,omitempty"`
		// source port
		SPort uint32 `json:"sport,omitempty"`
		// destination port
		DPort uint32 `json:"dport,omitempty"`
		// length packet
		Length uint32 `json:"len"`
		// ip protocol (tcp/udp/icmp/...)
		IpProto string `json:"proto"`
		// verdict for the rule
		Verdict string `json:"verdict"`
		// rule expression as string
		Rule string `json:"rule"`
		// aggregated trace counter
		Cnt uint64 `json:"cnt"`
		// timestamp
		Timestamp time.Time `json:"timestamp"`
	}
)

func (t *Trace) Hash() uint64 {
	return xxhash.Sum64String(t.IpProto + t.SAddr + t.DAddr + strconv.Itoa(int(t.SPort)) + strconv.Itoa(int(t.DPort)))
}

func (t *Trace) JsonString() string {
	b, _ := json.Marshal(t)
	return string(b)
}

func (t *Trace) FiveTuple() string {
	return fmt.Sprintf("src=%-25s dst=%-25s proto=%-8s",
		fmt.Sprintf("%s:%d", t.SAddr, t.SPort),
		fmt.Sprintf("%s:%d", t.DAddr, t.DPort),
		t.IpProto)
}
