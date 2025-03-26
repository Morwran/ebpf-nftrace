package parser

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	rb "github.com/Morwran/ebpf-nftrace/internal/nftables/bytes"

	"github.com/ahmetb/go-linq/v3"
	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	baseDec = 10
	baseHex = 16
)

type (
	SetElement nftLib.SetElement
	SetElems   []SetElement
	Set        nftLib.Set

	SetInfo struct {
		Type    nftLib.SetDatatype
		Table   *nftLib.Table
		SetName string
		SetId   uint32
		Elems   SetElems
	}
)

const (
	MagicTypeInvalid uint32 = iota
	MagicTypeVerdict
	MagicTypeNFProto
	MagicTypeBitmask
	MagicTypeInteger
	MagicTypeString
	MagicTypeLLAddr
	MagicTypeIPAddr
	MagicTypeIP6Addr
	MagicTypeEtherAddr
	MagicTypeEtherType
	MagicTypeARPOp
	MagicTypeInetProto
	MagicTypeInetService
	MagicTypeICMPType
	MagicTypeTCPFlag
	MagicTypeDCCPPktType
	MagicTypeMHType
	MagicTypeTime
	MagicTypeMark
	MagicTypeIFIndex
	MagicTypeARPHRD
	MagicTypeRealm
	MagicTypeClassID
	MagicTypeUID
	MagicTypeGID
	MagicTypeCTState
	MagicTypeCTDir
	MagicTypeCTStatus
	MagicTypeICMP6Type
	MagicTypeCTLabel
	MagicTypePktType
	MagicTypeICMPCode
	MagicTypeICMPV6Code
	MagicTypeICMPXCode
	MagicTypeDevGroup
	MagicTypeDSCP
	MagicTypeECN
	MagicTypeFIBAddr
	MagicTypeBoolean
	MagicTypeCTEventBit
	MagicTypeIFName
	MagicTypeIGMPType
	MagicTypeTimeDate
	MagicTypeTimeHour
	MagicTypeTimeDay
	MagicTypeCGroupV2
)

var nftDatatypesByMagic = map[uint32]nftLib.SetDatatype{
	MagicTypeVerdict:     nftLib.TypeVerdict,
	MagicTypeNFProto:     nftLib.TypeNFProto,
	MagicTypeBitmask:     nftLib.TypeBitmask,
	MagicTypeInteger:     nftLib.TypeInteger,
	MagicTypeString:      nftLib.TypeString,
	MagicTypeLLAddr:      nftLib.TypeLLAddr,
	MagicTypeIPAddr:      nftLib.TypeIPAddr,
	MagicTypeIP6Addr:     nftLib.TypeIP6Addr,
	MagicTypeEtherAddr:   nftLib.TypeEtherAddr,
	MagicTypeEtherType:   nftLib.TypeEtherType,
	MagicTypeARPOp:       nftLib.TypeARPOp,
	MagicTypeInetProto:   nftLib.TypeInetProto,
	MagicTypeInetService: nftLib.TypeInetService,
	MagicTypeICMPType:    nftLib.TypeICMPType,
	MagicTypeTCPFlag:     nftLib.TypeTCPFlag,
	MagicTypeDCCPPktType: nftLib.TypeDCCPPktType,
	MagicTypeMHType:      nftLib.TypeMHType,
	MagicTypeTime:        nftLib.TypeTime,
	MagicTypeMark:        nftLib.TypeMark,
	MagicTypeIFIndex:     nftLib.TypeIFIndex,
	MagicTypeARPHRD:      nftLib.TypeARPHRD,
	MagicTypeRealm:       nftLib.TypeRealm,
	MagicTypeClassID:     nftLib.TypeClassID,
	MagicTypeUID:         nftLib.TypeUID,
	MagicTypeGID:         nftLib.TypeGID,
	MagicTypeCTState:     nftLib.TypeCTState,
	MagicTypeCTDir:       nftLib.TypeCTDir,
	MagicTypeCTStatus:    nftLib.TypeCTStatus,
	MagicTypeICMP6Type:   nftLib.TypeICMP6Type,
	MagicTypeCTLabel:     nftLib.TypeCTLabel,
	MagicTypePktType:     nftLib.TypePktType,
	MagicTypeICMPCode:    nftLib.TypeICMPCode,
	MagicTypeICMPV6Code:  nftLib.TypeICMPV6Code,
	MagicTypeICMPXCode:   nftLib.TypeICMPXCode,
	MagicTypeDevGroup:    nftLib.TypeDevGroup,
	MagicTypeDSCP:        nftLib.TypeDSCP,
	MagicTypeECN:         nftLib.TypeECN,
	MagicTypeFIBAddr:     nftLib.TypeFIBAddr,
	MagicTypeBoolean:     nftLib.TypeBoolean,
	MagicTypeCTEventBit:  nftLib.TypeCTEventBit,
	MagicTypeIFName:      nftLib.TypeIFName,
	MagicTypeIGMPType:    nftLib.TypeIGMPType,
	MagicTypeTimeDate:    nftLib.TypeTimeDate,
	MagicTypeTimeHour:    nftLib.TypeTimeHour,
	MagicTypeTimeDay:     nftLib.TypeTimeDay,
	MagicTypeCGroupV2:    nftLib.TypeCGroupV2,
}

func (set *Set) InitFromMsg(msg netlink.Message) error {
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_NAME:
			set.Name = ad.String()
		case unix.NFTA_SET_TABLE:
			set.Table = &nftLib.Table{Name: ad.String()}
			// msg[0] carries TableFamily byte indicating whether it is IPv4, IPv6 or something else
			set.Table.Family = nftLib.TableFamily(msg.Data[0])
		case unix.NFTA_SET_ID:
			set.ID = binary.BigEndian.Uint32(ad.Bytes())
		case unix.NFTA_SET_TIMEOUT:
			set.Timeout = time.Millisecond * time.Duration(binary.BigEndian.Uint64(ad.Bytes())) //nolint:gosec
			set.HasTimeout = true
		case unix.NFTA_SET_FLAGS:
			flags := ad.Uint32()
			set.Constant = (flags & unix.NFT_SET_CONSTANT) != 0
			set.Anonymous = (flags & unix.NFT_SET_ANONYMOUS) != 0
			set.Interval = (flags & unix.NFT_SET_INTERVAL) != 0
			set.IsMap = (flags & unix.NFT_SET_MAP) != 0
			set.HasTimeout = (flags & unix.NFT_SET_TIMEOUT) != 0
			set.Concatenation = (flags & nftLib.NFT_SET_CONCAT) != 0
		case unix.NFTA_SET_KEY_TYPE:
			nftMagic := ad.Uint32()
			dt, err := parseSetDatatype(nftMagic)
			if err != nil {
				return fmt.Errorf("could not determine data type: %w", err)
			}
			set.KeyType = dt
		case unix.NFTA_SET_KEY_LEN:
			set.KeyType.Bytes = binary.BigEndian.Uint32(ad.Bytes())
		case unix.NFTA_SET_DATA_TYPE:
			nftMagic := ad.Uint32()
			// Special case for the data type verdict, in the message it is stored as 0xffffff00 but it is defined as 1
			if nftMagic == 0xffffff00 { //nolint:mnd
				set.KeyType = nftLib.TypeVerdict
				break
			}
			dt, err := parseSetDatatype(nftMagic)
			if err != nil {
				return fmt.Errorf("could not determine data type: %w", err)
			}
			set.DataType = dt
		case unix.NFTA_SET_DATA_LEN:
			set.DataType.Bytes = binary.BigEndian.Uint32(ad.Bytes())
		}
	}
	return nil
}

func (s *Set) Flags() (flags []string) {
	if s.Constant {
		flags = append(flags, "constant")
	}

	if s.Anonymous {
		flags = append(flags, "anonymous")
	}

	if s.Interval {
		flags = append(flags, "interval")
	}

	if s.IsMap {
		flags = append(flags, "map")
	}

	if s.HasTimeout {
		flags = append(flags, "timeout")
	}

	if s.Concatenation {
		flags = append(flags, "concatenation")
	}

	return
}

func (s *Set) String(elems ...string) string {
	sb := strings.Builder{}
	if s.Anonymous {
		return ""
	}

	sb.WriteString(fmt.Sprintf("set %s {\n\t\ttype %s\n\t\tflags %s\n\t\telements = { ",
		s.Name, s.KeyType.Name, strings.Join(s.Flags(), ",")))

	sb.WriteString(strings.Join(elems, ","))

	sb.WriteString(" }\n\t}")
	return sb.String()
}

func (set *SetInfo) InitFromMsg(msg netlink.Message) error {
	fam := msg.Data[0]
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		b := ad.Bytes()
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_LIST_TABLE:
			set.Table = &nftLib.Table{Name: ad.String(), Family: nftLib.TableFamily(fam)}
		case unix.NFTA_SET_ELEM_LIST_SET:
			set.SetName = ad.String()
		case unix.NFTA_SET_ELEM_LIST_SET_ID:
			set.SetId = ad.Uint32()
		case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
			ad, err := netlink.NewAttributeDecoder(b)
			if err != nil {
				return err
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				var elem SetElement
				if ad.Type() == unix.NFTA_LIST_ELEM {
					ad.Do(elem.decode(fam))
					if ad.Err() != nil {
						return ad.Err()
					}
					set.Elems = append(set.Elems, elem)
				}
			}
		}
	}

	return nil
}

func (s SetElems) SortAs(typ nftLib.SetDatatype) SetElems {
	sortedElements := make(SetElems, 0, len(s))
	linq.From(s).
		OrderBy(func(i interface{}) interface{} {
			elem := i.(SetElement)
			switch typ {
			case nftLib.TypeVerdict,
				nftLib.TypeString,
				nftLib.TypeIFName:
				return 0
			}
			return rb.RawBytes(elem.Key).Uint64()
		}).
		ToSlice(&sortedElements)

	return sortedElements
}

func (s *SetInfo) String() string {
	sb := strings.Builder{}
	formatter := getElementFormatter(s.Type)
	for _, elem := range s.Elems.SortAs(s.Type) {
		if elem.IntervalEnd {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(formatter(elem).String())
	}
	return sb.String()
}

type (
	SetElementTypeString SetElement
	SetElementTypeIp     SetElement
	SetElementTypeHex    SetElement
	SetElementTypeDec    SetElement
)

func (s SetElementTypeString) String() string {
	return rb.RawBytes(s.Key).String()
}

func (s SetElementTypeIp) String() string {
	rb.RawBytes(s.Key).Uint64()
	return rb.RawBytes(s.Key).Ip().String()
}

func (s SetElementTypeHex) String() string {
	return rb.RawBytes(s.Key).Text(baseHex)
}

func (s SetElementTypeDec) String() string {
	return rb.RawBytes(s.Key).Text(baseDec)
}

func (s *SetElement) decode(fam byte) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return fmt.Errorf("failed to create nested attribute decoder: %v", err)
		}
		ad.ByteOrder = binary.BigEndian

		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_SET_ELEM_KEY:
				s.Key, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case nftLib.NFTA_SET_ELEM_KEY_END:
				s.KeyEnd, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case unix.NFTA_SET_ELEM_DATA:
				s.Val, err = decodeElement(ad.Bytes())
				if err != nil {
					return err
				}
			case unix.NFTA_SET_ELEM_FLAGS:
				flags := ad.Uint32()
				s.IntervalEnd = (flags & unix.NFT_SET_ELEM_INTERVAL_END) != 0
			case unix.NFTA_SET_ELEM_TIMEOUT:
				s.Timeout = time.Millisecond * time.Duration(ad.Uint64()) //nolint:gosec
			case unix.NFTA_SET_ELEM_EXPIRATION:
				s.Expires = time.Millisecond * time.Duration(ad.Uint64()) //nolint:gosec
			case unix.NFTA_SET_ELEM_EXPR:
				elems, err := ParseExprBytesFunc(fam, ad, ad.Bytes())
				if err != nil {
					return err
				}

				for _, elem := range elems {
					switch item := elem.(type) {
					case *expr.Counter:
						s.Counter = item
					}
				}
			}
		}
		return ad.Err()
	}
}

func getElementFormatter(typ nftLib.SetDatatype) func(elem SetElement) fmt.Stringer {
	return func(elem SetElement) fmt.Stringer {
		switch typ {
		case nftLib.TypeVerdict,
			nftLib.TypeString,
			nftLib.TypeIFName:
			return SetElementTypeString(elem)
		case nftLib.TypeIPAddr,
			nftLib.TypeIP6Addr:
			return SetElementTypeIp(elem)
		case nftLib.TypeBitmask,
			nftLib.TypeLLAddr,
			nftLib.TypeEtherAddr,
			nftLib.TypeTCPFlag,
			nftLib.TypeMark,
			nftLib.TypeUID,
			nftLib.TypeGID:
			return SetElementTypeHex(elem)
		}
		return SetElementTypeDec(elem)
	}
}

func parseSetDatatype(magic uint32) (nftLib.SetDatatype, error) {
	types := make([]nftLib.SetDatatype, 0, 32/nftLib.SetConcatTypeBits) //nolint:mnd
	for magic != 0 {
		t := magic & nftLib.SetConcatTypeMask
		magic = magic >> nftLib.SetConcatTypeBits
		dt, ok := nftDatatypesByMagic[t]
		if !ok {
			return nftLib.TypeInvalid, fmt.Errorf("could not determine data type %+v", dt)
		}
		// Because we start with the last type, we insert the later types at the front.
		types = append([]nftLib.SetDatatype{dt}, types...)
	}

	dt, err := nftLib.ConcatSetType(types...)
	if err != nil {
		return nftLib.TypeInvalid, fmt.Errorf("could not create data type: %w", err)
	}
	return dt, nil
}

func decodeElement(d []byte) ([]byte, error) {
	ad, err := netlink.NewAttributeDecoder(d)
	if err != nil {
		return nil, fmt.Errorf("failed to create nested attribute decoder: %v", err)
	}
	ad.ByteOrder = binary.BigEndian
	var b []byte
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_ELEM_KEY:
			fallthrough
		case unix.NFTA_SET_ELEM_DATA:
			b = ad.Bytes()
		}
	}
	if err = ad.Err(); err != nil {
		return nil, err
	}
	return b, nil
}
