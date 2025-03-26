package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_TraceJson(t *testing.T) {
	trace := Trace{
		TrId: 123,
		// nftables table name
		Table: "tb1",
		// nftables chain name
		Chain: "ch1",
		// nftables jump to a target name
		JumpTarget: "jt1",
		// nftables rule number
		RuleHandle: 5,
		// rule expression
		Rule: "rule",
		// verdict for the rule
		Verdict: "accept",
		// input network interface
		Iifname: "eth0",
		// output network interface
		Oifname: "eth1",
		// protocols family
		Family: "ip",
		// ip protocol (tcp/udp/icmp/...)
		IpProto: "tcp",
		// length packet
		Length: 123,
		// source mac address
		SMacAddr: "00:00:00:00:00:00",
		// destination mac address
		DMacAddr: "00:00:00:00:00:00",
		// source ip address
		SAddr: "192.168.0.1",
		// destination ip address
		DAddr: "192.168.0.2",
		// source port
		SPort: 80,
		// destination port
		DPort: 443,
		// aggregated trace counter
		Cnt: 10,
		Timestamp: func() time.Time {
			t, _ := time.Parse("2006-01-02 15:04:05", "2024-09-28 01:11:14")
			return t
		}(),
	}
	expJson := `{"trace_id":123,"table_name":"tb1","chain_name":"ch1","jt":"jt1","handle":5,"family":"ip","iif":"eth0","oif":"eth1","hw-src":"00:00:00:00:00:00","hw-dst":"00:00:00:00:00:00","ip-src":"192.168.0.1","ip-dst":"192.168.0.2","sport":80,"dport":443,"len":123,"proto":"tcp","verdict":"accept","rule":"rule","cnt":10,"timestamp":"2024-09-28T01:11:14Z"}`

	require.Equal(t, expJson, trace.JsonString())
}
