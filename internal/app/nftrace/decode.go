package nftrace

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

type (
	Verdict     int32
	FamilyTable uint8
	TraceType   uint8
	IpProto     uint8
)

/* Responses from hook functions. */
const (
	NF_DROP        = 0
	NF_ACCEPT      = 1
	NF_STOLEN      = 2
	NF_QUEUE       = 3
	NF_REPEAT      = 4
	NF_STOP        = 5 /* Deprecated, for userspace nf_queue compatibility. */
	NF_MAX_VERDICT = NF_STOP
)

const ICMP_REDIRECT = 5

func (v Verdict) String() string {
	switch v { //nolint:gosec
	case NF_ACCEPT:
		return "accept"

	case NF_DROP:
		return "drop"

	case NF_STOLEN:
		return "stolen"

	case NF_QUEUE:
		return "queue"

	case NF_REPEAT:
		return "repeat"

	case NF_STOP:
		return "stop"

	case unix.NFT_RETURN:
		return "return"

	case unix.NFT_JUMP:
		return "jump"

	case unix.NFT_GOTO:
		return "goto"

	case unix.NFT_CONTINUE:
		return "continue"

	case unix.NFT_BREAK:
		return "break"
	}

	return "unknown"
}

func (f FamilyTable) String() string {
	switch f {
	case unix.NFPROTO_IPV4:
		return "ip"

	case unix.NFPROTO_IPV6:
		return "ip6"

	case unix.NFPROTO_INET:
		return "inet"

	case unix.NFPROTO_NETDEV:
		return "netdev"

	case unix.NFPROTO_ARP:
		return "arp"

	case unix.NFPROTO_BRIDGE:
		return "bridge"
	}

	return "unknown"
}

func (t TraceType) String() string {
	switch t {
	case unix.NFT_TRACETYPE_UNSPEC:
		return "unspec"
	case unix.NFT_TRACETYPE_POLICY:
		return "policy"
	case unix.NFT_TRACETYPE_RETURN:
		return "return"
	case unix.NFT_TRACETYPE_RULE:
		return "rule"
	}
	return "unknown"
}

func (p IpProto) String() string {
	switch p {
	case unix.IPPROTO_TCP:
		return "tcp"

	case unix.IPPROTO_UDP:
		return "udp"

	case unix.IPPROTO_UDPLITE:
		return "udplite"

	case unix.IPPROTO_ESP:
		return "esp"

	case unix.IPPROTO_AH:
		return "ah"

	case unix.IPPROTO_ICMP:
		return "icmp"

	case unix.IPPROTO_ICMPV6:
		return "icmpv6"

	case unix.IPPROTO_COMP:
		return "comp"

	case unix.IPPROTO_DCCP:
		return "dccp"

	case unix.IPPROTO_SCTP:
		return "sctp"

	case ICMP_REDIRECT:
		return "redirect"
	}

	return "unknown"
}

func Ip2String(isIp6 bool, ip4 uint32, ip6 []byte) string {
	if isIp6 {
		return net.IP(ip6[:]).String()
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ip4)
	return ip.String()
}
