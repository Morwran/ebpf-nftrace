package nlheaders

import (
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
)

const (
	// Network ipv4 layer header length
	NlHeaderLenIPv4 = 20
	// Network ipv6 layer header length
	NlHeaderLenIPv6 = 40

	IPv4Version = 4
	IPv6Version = 6
)

// TODO: add other protocol support
// Network layer header
type NlHeader struct {
	Version        uint8 // 4 bits
	IHL            uint8 // 4 bits
	DSCP           uint8 // 6 bits
	ECN            uint8 // 2 bits
	Length         uint16
	Identification uint16
	Flags          uint8  // 3 bits
	FragmentOffset uint16 // 13 bits
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SAddr          net.IP
	DAddr          net.IP
	Options        []byte // optional, exists if IHL > 5
}

// Decode - decode header from byte stream
func (h *NlHeader) Decode(b []byte) (err error) {
	if l := len(b); l < 1 {
		return errors.Errorf("incorrect network layer header length=%d", l)
	}
	version := b[0] >> 4
	defer func() {
		if err == nil {
			h.Version = version
		}
	}()
	switch version {
	case IPv4Version:
		err = h.decodeIPv4(b)
	case IPv6Version:
		err = h.decodeIPv6(b)
	}

	return err
}

func (h *NlHeader) decodeIPv4(b []byte) error {
	l := len(b)
	if l < NlHeaderLenIPv4 {
		return errors.Errorf("incorrect network ipv4 layer header length=%d", l)
	}

	h.IHL = b[0] & 0x0F

	h.DSCP = b[1] >> 2
	h.ECN = b[1] & 0x03

	h.Length = binary.BigEndian.Uint16(b[2:4])
	h.Identification = binary.BigEndian.Uint16(b[4:6])

	h.Flags = b[6] >> 5

	h.FragmentOffset = binary.BigEndian.Uint16(b[6:8]) & 0x1FFF

	h.TTL = b[8]
	h.Protocol = b[9]
	h.HeaderChecksum = binary.BigEndian.Uint16(b[10:12])

	h.SAddr = make(net.IP, net.IPv4len)
	h.DAddr = make(net.IP, net.IPv4len)

	copy(h.SAddr, b[12:16])
	copy(h.DAddr, b[16:20])

	if h.IHL > 5 && l > NlHeaderLenIPv4 {
		h.Options = make([]byte, l-NlHeaderLenIPv4)
		copy(h.Options, b[NlHeaderLenIPv4:])
	}

	return nil
}

func (h *NlHeader) decodeIPv6(b []byte) error {
	l := len(b)
	if l < NlHeaderLenIPv6 {
		return errors.Errorf("incorrect network ipv6 layer header length=%d", l)
	}
	h.Length = binary.BigEndian.Uint16(b[4:6])
	h.Protocol = b[6]
	h.SAddr = make(net.IP, net.IPv6len)
	h.DAddr = make(net.IP, net.IPv6len)

	copy(h.SAddr, b[8:24])
	copy(h.DAddr, b[24:40])

	if l > NlHeaderLenIPv6 {
		h.Options = make([]byte, l-NlHeaderLenIPv6)
		copy(h.Options, b[NlHeaderLenIPv6:])
	}

	return nil
}
