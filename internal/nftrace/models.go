package nftrace

import (
	"bytes"
	"encoding/binary"
	"net"
	"unsafe"

	"github.com/Morwran/ebpf-nftrace/internal/nl/nlheaders"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type (
	EbpfTrace bpfTraceInfo

	NftTrace struct {
		Table      string
		Chain      string
		JumpTarget string
		RuleHandle uint64
		Family     byte
		Type       uint32
		Id         uint32
		Iif        uint32
		Oif        uint32
		Mark       uint32
		Verdict    uint32
		Nfproto    uint32
		Policy     uint32
		Iiftype    uint16
		Oiftype    uint16
		Iifname    string
		Oifname    string
		SMacAddr   string
		DMacAddr   string
		SAddr      string
		DAddr      string
		SPort      uint32
		DPort      uint32
		Length     uint32
		IpProtocol uint8
		Cnt        uint64
	}

	NetlinkTrace struct {
		Table      string
		Chain      string
		JumpTarget string
		RuleHandle uint64
		Lh         nlheaders.LlHeader
		Nh         nlheaders.NlHeader
		Th         nlheaders.TlHeader
		Family     byte
		Type       uint32
		Id         uint32
		Iif        uint32
		Oif        uint32
		Mark       uint32
		Verdict    uint32
		Nfproto    uint32
		Policy     uint32
		Iiftype    uint16
		Oiftype    uint16
	}

	FastHardwareAddr net.HardwareAddr
)

func (n *NftTrace) Reset() {
	*n = NftTrace{}
}

func (t *EbpfTrace) ToNftTrace() NftTrace {
	return NftTrace{
		Table:      FastBytes2String(bytes.TrimRight(t.TableName[:], "\x00")),
		Chain:      FastBytes2String(bytes.TrimRight(t.ChainName[:], "\x00")),
		JumpTarget: FastBytes2String(bytes.TrimRight(t.JumpTarget[:], "\x00")),
		RuleHandle: t.RuleHandle,
		Family:     t.Family,
		Type:       uint32(t.Type),
		Id:         t.Id,
		Iif:        t.Iif,
		Oif:        t.Oif,
		Mark:       t.Mark,
		Verdict:    t.Verdict,
		Nfproto:    uint32(t.Nfproto),
		Policy:     uint32(t.Policy),
		Iiftype:    t.IifType,
		Oiftype:    t.OifType,
		Iifname:    FastBytes2String(bytes.TrimRight(t.IifName[:], "\x00")),
		Oifname:    FastBytes2String(bytes.TrimRight(t.OifName[:], "\x00")),
		SMacAddr:   FastHardwareAddr(t.SrcMac[:]).String(),
		DMacAddr:   FastHardwareAddr(t.DstMac[:]).String(),
		SAddr:      Ip2String(t.Family == unix.NFPROTO_IPV6, t.SrcIp, t.SrcIp6.In6U.U6Addr8[:]),
		DAddr:      Ip2String(t.Family == unix.NFPROTO_IPV6, t.DstIp, t.DstIp6.In6U.U6Addr8[:]),
		SPort:      uint32(t.SrcPort),
		DPort:      uint32(t.DstPort),
		Length:     uint32(t.Len),
		IpProtocol: t.IpProto,
		Cnt:        t.Counter,
	}
}

func (tr *NetlinkTrace) InitFromMsg(msg netlink.Message) error {
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_TRACE_ID:
			tr.Id = ad.Uint32()
		case unix.NFTA_TRACE_TYPE:
			tr.Type = ad.Uint32()
		case unix.NFTA_TRACE_TABLE:
			tr.Table = ad.String()
		case unix.NFTA_TRACE_CHAIN:
			tr.Chain = ad.String()
		case unix.NFTA_TRACE_VERDICT:
			ad, err := netlink.NewAttributeDecoder(ad.Bytes())
			if err != nil {
				return err
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				switch ad.Type() {
				case unix.NFTA_VERDICT_CODE:
					tr.Verdict = ad.Uint32()
				case unix.NFTA_VERDICT_CHAIN:
					if int32(tr.Verdict) == unix.NFT_GOTO || //nolint:gosec
						int32(tr.Verdict) == unix.NFT_JUMP { //nolint:gosec
						tr.JumpTarget = ad.String()
					}
				}
			}
		case unix.NFTA_TRACE_IIFTYPE:
			tr.Iiftype = ad.Uint16()
		case unix.NFTA_TRACE_IIF:
			tr.Iif = ad.Uint32()
		case unix.NFTA_TRACE_OIFTYPE:
			tr.Oiftype = ad.Uint16()
		case unix.NFTA_TRACE_OIF:
			tr.Oif = ad.Uint32()
		case unix.NFTA_TRACE_MARK:
			tr.Mark = ad.Uint32()
		case unix.NFTA_TRACE_RULE_HANDLE:
			tr.RuleHandle = ad.Uint64()
		case unix.NFTA_TRACE_LL_HEADER:
			if err = tr.Lh.Decode(ad.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_TRACE_NETWORK_HEADER:
			if err = tr.Nh.Decode(ad.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_TRACE_TRANSPORT_HEADER:
			if err = tr.Th.Decode(ad.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_TRACE_NFPROTO:
			tr.Nfproto = ad.Uint32()
		case unix.NFTA_TRACE_POLICY:
			tr.Policy = ad.Uint32()
		}
	}
	tr.Family = msg.Data[0]
	return nil
}

func (tr *NetlinkTrace) ToNftTrace() NftTrace {
	return NftTrace{
		Table:      tr.Table,
		Chain:      tr.Chain,
		JumpTarget: tr.JumpTarget,
		RuleHandle: tr.RuleHandle,
		Family:     tr.Family,
		Type:       tr.Type,
		Id:         tr.Id,
		Iif:        tr.Iif,
		Oif:        tr.Oif,
		Mark:       tr.Mark,
		Verdict:    tr.Verdict,
		Nfproto:    tr.Nfproto,
		Policy:     tr.Policy,
		Iiftype:    tr.Iiftype,
		Oiftype:    tr.Oiftype,
		SMacAddr:   FastHardwareAddr(tr.Lh.SAddr).String(),
		DMacAddr:   FastHardwareAddr(tr.Lh.DAddr).String(),
		SAddr:      tr.Nh.SAddr.String(),
		DAddr:      tr.Nh.DAddr.String(),
		SPort:      uint32(tr.Th.SPort),
		DPort:      uint32(tr.Th.DPort),
		Length:     uint32(tr.Nh.Length),
		IpProtocol: tr.Nh.Protocol,
		Cnt:        1,
	}
}

func (a FastHardwareAddr) String() string {
	const hexDigit = "0123456789abcdef"
	if len(a) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(a)*3-1)
	for i, b := range a {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return FastBytes2String(buf)
}

func Ip2String(isIp6 bool, ip4 uint32, ip6 []byte) string {
	if isIp6 {
		return net.IP(ip6[:]).String()
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip4)
	return net.IP(b[:]).String()
}

func FastBytes2String(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
