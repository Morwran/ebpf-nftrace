package protocols

import (
	"math/bits"
	"strings"

	"github.com/Morwran/ebpf-nftrace/internal/nftables/bytes"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

/*
	protocol:
		0 - ip
		1 - icmp
		2 - igmp
		3 - ggp
		4 - ipencap
		5 - st
		6 - tcp
		8 - egp
		9 - igp
		12 - pup
		17 - udp
*/

type (
	HeaderOffset   uint32
	ProtoHdrHolder map[HeaderOffset]ProtoHdrDesc
	ProtoHdrDesc   struct {
		Name string
		Desc func(b []byte) string
	}
	ProtoDesc struct {
		Name          string
		Id            ProtoType
		Base          expr.PayloadBase
		CurrentOffset HeaderOffset
		Offsets       ProtoHdrHolder
	}
	ProtoDescPtr     *ProtoDesc
	ProtoTypeHolder  map[ProtoType]ProtoDesc
	ProtoLayerHolder map[expr.PayloadBase]ProtoTypeHolder
)

func (nbytes HeaderOffset) BytesToBits() HeaderOffset {
	return HeaderOffset(byte(nbytes) * BitsPerByte)
}

func (offset HeaderOffset) WithBitMask(mask uint32) HeaderOffset {
	return offset + HeaderOffset(bits.LeadingZeros8(bits.Reverse8(uint8(mask)))) //nolint:gosec
}

const (
	ICMPHDR_TYPE     = HeaderOffset(byte(0) * BitsPerByte)
	ICMPHDR_CODE     = HeaderOffset(byte(1) * BitsPerByte)
	ICMPHDR_CHECKSUM = HeaderOffset(byte(2) * BitsPerByte)
	ICMPHDR_ID       = HeaderOffset(byte(4) * BitsPerByte)
	ICMPHDR_SEQ      = HeaderOffset(byte(6) * BitsPerByte)
	ICMPHDR_GATEWAY  = HeaderOffset(byte(8) * BitsPerByte)
	ICMPHDR_MTU      = HeaderOffset(byte(14) * BitsPerByte)
)

const (
	ICMP6HDR_TYPE     = HeaderOffset(byte(0) * BitsPerByte)
	ICMP6HDR_CODE     = HeaderOffset(byte(1) * BitsPerByte)
	ICMP6HDR_CHECKSUM = HeaderOffset(byte(2) * BitsPerByte)
	ICMP6HDR_PPTR     = HeaderOffset(byte(4) * BitsPerByte)
	ICMP6HDR_MTU      = HeaderOffset(byte(8) * BitsPerByte)
)

const (
	UDPHDR_SPORT    = HeaderOffset(byte(0) * BitsPerByte)
	UDPHDR_DPORT    = HeaderOffset(byte(2) * BitsPerByte)
	UDPHDR_LENGTH   = HeaderOffset(byte(4) * BitsPerByte)
	UDPHDR_CHECKSUM = HeaderOffset(byte(6) * BitsPerByte)
)

const (
	TCPHDR_SPORT    = HeaderOffset(byte(0) * BitsPerByte)
	TCPHDR_DPORT    = HeaderOffset(byte(2) * BitsPerByte)
	TCPHDR_SEQ      = HeaderOffset(byte(4) * BitsPerByte)
	TCPHDR_ACKSEQ   = HeaderOffset(byte(8) * BitsPerByte)
	TCPHDR_RESERVED = HeaderOffset(byte(12) * BitsPerByte)
	TCPHDR_DOFF     = HeaderOffset(byte(TCPHDR_RESERVED) + BitsPerHalfByte)
	TCPHDR_FLAGS    = HeaderOffset(byte(13) * BitsPerByte)
	TCPHDR_WINDOW   = HeaderOffset(byte(14) * BitsPerByte)
	TCPHDR_CHECKSUM = HeaderOffset(byte(16) * BitsPerByte)
	TCPHDR_URGPTR   = HeaderOffset(byte(18) * BitsPerByte)
)

const (
	THDR_SPORT HeaderOffset = HeaderOffset(byte(0) * BitsPerByte)
	THDR_DPORT HeaderOffset = HeaderOffset(byte(2) * BitsPerByte)
)

/*
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	//The options start here.
	};
*/

const (
	IPHDR_HDRLENGTH = HeaderOffset(byte(0) * BitsPerHalfByte)
	IPHDR_VERSION   = HeaderOffset(byte(IPHDR_HDRLENGTH) + BitsPerHalfByte)
	IPHDR_ECN       = HeaderOffset(byte(IPHDR_VERSION) + BitsPerHalfByte)
	IPHDR_DSCP      = HeaderOffset(byte(IPHDR_ECN) + BitsPerHalfByte)
	IPHDR_LENGTH    = HeaderOffset(byte(IPHDR_DSCP) + BitsPerHalfByte)
	IPHDR_ID        = HeaderOffset(byte(IPHDR_LENGTH) + 2*BitsPerByte)
	IPHDR_FRAG_OFF  = HeaderOffset(byte(IPHDR_ID) + 2*BitsPerByte)
	IPHDR_TTL       = HeaderOffset(byte(8) * BitsPerByte)
	IPHDR_PROTOCOL  = HeaderOffset(byte(9) * BitsPerByte)
	IPHDR_CHECKSUM  = HeaderOffset(byte(10) * BitsPerByte)
	IPHDR_SADDR     = HeaderOffset(byte(12) * BitsPerByte)
	IPHDR_DADDR     = HeaderOffset(byte(16) * BitsPerByte)
)

/*
struct ipv6hdr {
	uint8_t		version:4,
			priority:4;
	uint8_t		flow_lbl[3];

	uint16_t	payload_len;
	uint8_t		nexthdr;
	uint8_t		hop_limit;

	struct in6_addr	saddr;
	struct in6_addr	daddr;
};
*/

const (
	IP6HDR_VERSION   = HeaderOffset(byte(0) * BitsPerByte)
	IP6HDR_FLOWLABEL = HeaderOffset(byte(1) * BitsPerByte)
	IP6HDR_LENGTH    = HeaderOffset(byte(4) * BitsPerByte)
	IP6HDR_NEXTHDR   = HeaderOffset(byte(6) * BitsPerByte)
	IP6HDR_HOPLIMIT  = HeaderOffset(byte(7) * BitsPerByte)
	IP6HDR_SADDR     = HeaderOffset(byte(8) * BitsPerByte)
	IP6HDR_DADDR     = HeaderOffset(byte(24) * BitsPerByte)
)

var Protocols = ProtoLayerHolder{
	expr.PayloadBaseTransportHeader: {
		unix.IPPROTO_ICMP: ProtoDesc{
			Name:          "icmp",
			Id:            unix.IPPROTO_ICMP,
			Base:          expr.PayloadBaseTransportHeader,
			CurrentOffset: ICMPHDR_TYPE,
			Offsets: ProtoHdrHolder{
				ICMPHDR_TYPE:     ProtoHdrDesc{Name: "type", Desc: BytesToIcmpType},
				ICMPHDR_CODE:     ProtoHdrDesc{Name: "code", Desc: BytesToIcmpCode},
				ICMPHDR_CHECKSUM: ProtoHdrDesc{Name: "checksum", Desc: bytes.BytesToDecimalString},
				ICMPHDR_ID:       ProtoHdrDesc{Name: "id", Desc: bytes.BytesToDecimalString},
				ICMPHDR_SEQ:      ProtoHdrDesc{Name: "sequence", Desc: bytes.BytesToDecimalString},
				ICMPHDR_GATEWAY:  ProtoHdrDesc{Name: "gateway", Desc: bytes.BytesToDecimalString},
				ICMPHDR_MTU:      ProtoHdrDesc{Name: "mtu", Desc: bytes.BytesToDecimalString},
			},
		},
		unix.IPPROTO_ICMPV6: ProtoDesc{
			Name:          "icmpv6",
			Id:            unix.IPPROTO_ICMPV6,
			Base:          expr.PayloadBaseTransportHeader,
			CurrentOffset: ICMP6HDR_TYPE,
			Offsets: ProtoHdrHolder{
				ICMP6HDR_TYPE:     ProtoHdrDesc{Name: "type", Desc: BytesToIcmp6Type},
				ICMP6HDR_CODE:     ProtoHdrDesc{Name: "code", Desc: BytesToIcmp6Code},
				ICMP6HDR_CHECKSUM: ProtoHdrDesc{Name: "checksum", Desc: bytes.BytesToDecimalString},
				ICMP6HDR_PPTR:     ProtoHdrDesc{Name: "parameter-problem", Desc: bytes.BytesToDecimalString},
				ICMP6HDR_MTU:      ProtoHdrDesc{Name: "mtu", Desc: bytes.BytesToDecimalString},
			},
		},
		unix.IPPROTO_UDP: ProtoDesc{
			Name:          "udp",
			Id:            unix.IPPROTO_UDP,
			Base:          expr.PayloadBaseTransportHeader,
			CurrentOffset: UDPHDR_SPORT,
			Offsets: ProtoHdrHolder{
				UDPHDR_SPORT:    ProtoHdrDesc{Name: "sport", Desc: bytes.BytesToDecimalString},
				UDPHDR_DPORT:    ProtoHdrDesc{Name: "dport", Desc: bytes.BytesToDecimalString},
				UDPHDR_LENGTH:   ProtoHdrDesc{Name: "length", Desc: bytes.BytesToDecimalString},
				UDPHDR_CHECKSUM: ProtoHdrDesc{Name: "checksum", Desc: bytes.BytesToDecimalString},
			},
		},
		unix.IPPROTO_TCP: ProtoDesc{
			Name:          "tcp",
			Id:            unix.IPPROTO_TCP,
			Base:          expr.PayloadBaseTransportHeader,
			CurrentOffset: TCPHDR_SPORT,
			Offsets: ProtoHdrHolder{
				TCPHDR_SPORT:    ProtoHdrDesc{Name: "sport", Desc: bytes.BytesToDecimalString},
				TCPHDR_DPORT:    ProtoHdrDesc{Name: "dport", Desc: bytes.BytesToDecimalString},
				TCPHDR_SEQ:      ProtoHdrDesc{Name: "sequence", Desc: bytes.BytesToDecimalString},
				TCPHDR_ACKSEQ:   ProtoHdrDesc{Name: "ackseq", Desc: bytes.BytesToDecimalString},
				TCPHDR_RESERVED: ProtoHdrDesc{Name: "rederved", Desc: bytes.BytesToDecimalString},
				TCPHDR_DOFF:     ProtoHdrDesc{Name: "doff", Desc: bytes.BytesToDecimalString},
				TCPHDR_FLAGS:    ProtoHdrDesc{Name: "flags", Desc: BytesToTcpFlags},
				TCPHDR_WINDOW:   ProtoHdrDesc{Name: "window", Desc: bytes.BytesToDecimalString},
				TCPHDR_CHECKSUM: ProtoHdrDesc{Name: "checksum", Desc: bytes.BytesToDecimalString},
				TCPHDR_URGPTR:   ProtoHdrDesc{Name: "urgptr", Desc: bytes.BytesToDecimalString},
			},
		},
		unix.IPPROTO_NONE: ProtoDesc{
			Name:          "th",
			Id:            unix.IPPROTO_NONE,
			Base:          expr.PayloadBaseTransportHeader,
			CurrentOffset: THDR_SPORT,
			Offsets: ProtoHdrHolder{
				THDR_SPORT: ProtoHdrDesc{Name: "sport", Desc: bytes.BytesToDecimalString},
				THDR_DPORT: ProtoHdrDesc{Name: "dport", Desc: bytes.BytesToDecimalString},
			},
		},
	},
	expr.PayloadBaseNetworkHeader: {
		unix.IPPROTO_IP: ProtoDesc{
			Name:          "ip",
			Id:            unix.IPPROTO_IP,
			Base:          expr.PayloadBaseNetworkHeader,
			CurrentOffset: IPHDR_HDRLENGTH,
			Offsets: ProtoHdrHolder{
				IPHDR_HDRLENGTH: ProtoHdrDesc{Name: "hdrlength", Desc: bytes.BytesToDecimalString},
				IPHDR_VERSION:   ProtoHdrDesc{Name: "version", Desc: bytes.BytesToIPVer},
				IPHDR_ECN:       ProtoHdrDesc{Name: "ecn", Desc: bytes.BytesToEcn},
				IPHDR_DSCP:      ProtoHdrDesc{Name: "dscp", Desc: bytes.BytesToDscp},
				IPHDR_LENGTH:    ProtoHdrDesc{Name: "length", Desc: bytes.BytesToDecimalString},
				IPHDR_ID:        ProtoHdrDesc{Name: "id", Desc: bytes.BytesToDecimalString},
				IPHDR_FRAG_OFF:  ProtoHdrDesc{Name: "frag-off", Desc: bytes.BytesToHexString},
				IPHDR_TTL:       ProtoHdrDesc{Name: "ttl", Desc: bytes.BytesToDecimalString},
				IPHDR_PROTOCOL:  ProtoHdrDesc{Name: "protocol", Desc: BytesToProtoString},
				IPHDR_CHECKSUM:  ProtoHdrDesc{Name: "checksum", Desc: bytes.BytesToDecimalString},
				IPHDR_SADDR:     ProtoHdrDesc{Name: "saddr", Desc: bytes.BytesToAddrString},
				IPHDR_DADDR:     ProtoHdrDesc{Name: "daddr", Desc: bytes.BytesToAddrString},
			},
		},
		unix.IPPROTO_IPV6: ProtoDesc{
			Name:          "ip6",
			Id:            unix.IPPROTO_IPV6,
			Base:          expr.PayloadBaseNetworkHeader,
			CurrentOffset: IP6HDR_VERSION,
			Offsets: ProtoHdrHolder{
				IP6HDR_VERSION:   ProtoHdrDesc{Name: "version", Desc: bytes.BytesToDecimalString},
				IP6HDR_FLOWLABEL: ProtoHdrDesc{Name: "flowlabel", Desc: bytes.BytesToDecimalString},
				IP6HDR_LENGTH:    ProtoHdrDesc{Name: "length", Desc: bytes.BytesToDecimalString},
				IP6HDR_NEXTHDR:   ProtoHdrDesc{Name: "nexthdr", Desc: bytes.BytesToDecimalString},
				IP6HDR_HOPLIMIT:  ProtoHdrDesc{Name: "hoplimit", Desc: bytes.BytesToDecimalString},
				IP6HDR_SADDR:     ProtoHdrDesc{Name: "saddr", Desc: bytes.BytesToAddrString},
				IP6HDR_DADDR:     ProtoHdrDesc{Name: "daddr", Desc: bytes.BytesToAddrString},
			},
		},
	},
}

//Helpers...

func BytesToIcmpType(b []byte) string {
	return IcmpType(bytes.RawBytes(b).Uint64()).String() //nolint:gosec
}

func BytesToIcmpCode(b []byte) string {
	return IcmpCode(bytes.RawBytes(b).Uint64()).String() //nolint:gosec
}

func BytesToIcmp6Type(b []byte) string {
	return Icmp6Type(bytes.RawBytes(b).Uint64()).String() //nolint:gosec
}

func BytesToIcmp6Code(b []byte) string {
	return Icmp6Code(bytes.RawBytes(b).Uint64()).String() //nolint:gosec
}

func BytesToTcpFlags(b []byte) string {
	var flags []string
	fl := TcpFlagType(bytes.RawBytes(b).Uint64()) //nolint:gosec
	if fl&TCP_FLAG_FIN != 0 {
		flags = append(flags, TCP_FLAG_FIN.String())
	}
	if fl&TCP_FLAG_SYN != 0 {
		flags = append(flags, TCP_FLAG_SYN.String())
	}
	if fl&TCP_FLAG_RST != 0 {
		flags = append(flags, TCP_FLAG_RST.String())
	}
	if fl&TCP_FLAG_PSH != 0 {
		flags = append(flags, TCP_FLAG_PSH.String())
	}
	if fl&TCP_FLAG_ACK != 0 {
		flags = append(flags, TCP_FLAG_ACK.String())
	}
	if fl&TCP_FLAG_URG != 0 {
		flags = append(flags, TCP_FLAG_URG.String())
	}
	if fl&TCP_FLAG_ECN != 0 {
		flags = append(flags, TCP_FLAG_ECN.String())
	}
	if fl&TCP_FLAG_CWR != 0 {
		flags = append(flags, TCP_FLAG_CWR.String())
	}

	return strings.Join(flags, ",")
}

func BytesToProtoString(b []byte) string {
	return ProtoType(int(bytes.RawBytes(b).Uint64())).String() //nolint:gosec
}
