package nftrace

import "golang.org/x/sys/unix"

type (
	Verdict     int32
	FamilyTable int32
	TraceType   uint32
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
