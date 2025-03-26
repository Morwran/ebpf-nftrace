package nl

import (
	"context"
	"os"
	"sync"
	"syscall"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/socket"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// Overload netlink message for the netfilter
type NetlinkNfMsg netlink.Message

var _ NlNfMsg = (*NetlinkNfMsg)(nil)

func (n NetlinkNfMsg) MsgType() uint16 {
	return uint16(n.Header.Type) & ^NlSubsysMask
}

func (n NetlinkNfMsg) DataOffset(offset int) []byte {
	return n.Data[offset:]
}

type (
	Nl struct {
		sock      Conn
		timeout   *unix.Timeval
		bufflen   int
		close     chan struct{}
		stopped   chan struct{}
		data      []chan NlData
		closeOnce sync.Once
	}
	nlReaderImpl struct {
		data chan NlData
	}
	nlOpt interface {
		apply(*Nl) error
	}

	nlOptFunc func(*Nl) error
)

var _ NetlinkWatcher = (*Nl)(nil)

// NewNetlinkWatcher -
func NewNetlinkWatcher(ctx context.Context, splitOut int, proto int, opts ...nlOpt) (NetlinkWatcher, error) {
	var err error
	if splitOut <= 0 {
		return nil, errors.WithMessage(err, "number of watcher output data copies must be > 0")
	}
	watcher := &Nl{
		timeout: &unix.Timeval{ //timeout for receiving messages as default value
			Sec:  1,
			Usec: 0,
		},
		bufflen: os.Getpagesize(),
		close:   make(chan struct{}),
		stopped: make(chan struct{}),
		data:    make([]chan NlData, splitOut),
	}

	watcher.sock.Conn, err = socket.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW,
		proto,
		"netlink",
		nil,
	)

	if err != nil {
		return nil, errors.WithMessage(err, "failed to create 'netlink' socket")
	}

	defer func() {
		if err != nil {
			_ = watcher.sock.Close()
		}
	}()

	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
	}

	if err = watcher.sock.Bind(addr); err != nil {
		return nil, errors.WithMessage(err, "failed to bind(unix.AF_NETLINK) addr to socket")
	}

	err = watcher.sock.SetReadBuffer(watcher.bufflen)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to set receive buffer size for socket")
	}
	for _, o := range opts {
		if err = o.apply(watcher); err != nil {
			return nil, errors.WithMessage(err, "failed to init from options")
		}
	}

	for i := range watcher.data {
		watcher.data[i] = make(chan NlData)
	}

	go watcher.run(ctx)

	return watcher, nil
}

func (n *nlReaderImpl) Read() <-chan NlData {
	return n.data
}

// Reader -
func (n *Nl) Reader(readerID int) NlReader {
	return &nlReaderImpl{data: n.data[readerID]}
}

// Close -
func (n *Nl) Close() (err error) {
	n.closeOnce.Do(func() {
		err = n.sock.Close()
		close(n.close)
		<-n.stopped
	})
	return err
}

func (n *Nl) run(ctx context.Context) {
	defer close(n.stopped)
	var (
		err      error
		messages []netlink.Message
		rcvBuff  = make([]byte, n.bufflen)
	)
	const dataChanLen = 1024
	dataChan := make(chan NlData, dataChanLen)
	defer close(dataChan)

	go func() {
		defer func() {
			for i := range n.data {
				close(n.data[i])
			}
		}()
		for data := range dataChan {
			for i := range n.data {
				select {
				case <-n.close:
					return
				case <-ctx.Done():
					return
				case n.data[i] <- data:
				}
			}
		}
	}()

	for {
		messages, err = n.rcv(rcvBuff)
		if errors.Is(err, ErrNlDataNotReady) {
			continue
		}

		select {
		case <-n.close:
			return
		case <-ctx.Done():
			err = ctx.Err()
			select {
			case dataChan <- NlData{messages, err}:
			default:
			}
			return
		case dataChan <- NlData{messages, err}:
		}
	}
}

func (n *Nl) rcv(rcvBuff []byte) ([]netlink.Message, error) {
	var (
		length int
		err    error
	)

loop:
	length, err = n.sock.TryRecv(rcvBuff, n.timeout)
	if err != nil {
		var ern syscall.Errno
		if errors.As(err, &ern) {
			if ern.Temporary() {
				return nil, errors.Wrap(ErrNlReadInterrupted, err.Error())
			}
			if ern == unix.ENOBUFS || ern == unix.ENOMEM {
				return nil, errors.Wrap(ErrNlMem, err.Error())
			}
		}

		return nil, errors.WithMessage(err, "failed to read netlink data")
	}
	if length == 0 {
		rcvBuff = rcvBuff[0:]
		goto loop
	}

	messages, err := syscall.ParseNetlinkMessage(rcvBuff[:nlmsgAlign(length)])
	if err != nil {
		return nil, errors.WithMessage(err, "failed to parse netlink message")
	}

	nlMsgs := make([]netlink.Message, 0, len(messages))

	for _, msg := range messages {
		m := netlink.Message{
			Data: append([]byte(nil), msg.Data...),
			Header: netlink.Header{
				Length:   msg.Header.Len,
				Type:     netlink.HeaderType(msg.Header.Type),
				Flags:    netlink.HeaderFlags(msg.Header.Flags),
				Sequence: msg.Header.Seq,
				PID:      msg.Header.Pid,
			},
		}
		nlMsgs = append(nlMsgs, m)
	}

	return nlMsgs, nil
}

func (f nlOptFunc) apply(o *Nl) error {
	return f(o)
}

// NlWithTimeout - set timeout for receiving messages, default is 1 sec
func NlWithTimeout(t *unix.Timeval) nlOpt {
	return nlOptFunc(func(o *Nl) error {
		o.timeout = t
		return nil
	})
}

// WithReadBuffLen - set socket receive buffer size in bytes, default is Page size (4096 bites)
func WithReadBuffLen(bytes int) nlOpt {
	return nlOptFunc(func(o *Nl) error {
		o.bufflen = bytes
		return o.sock.SetReadBuffer(bytes)
	})
}

// WithNetlinkGroups - subscribe to netlink group
func WithNetlinkGroups(nlms ...int) nlOpt {
	return nlOptFunc(func(o *Nl) error {
		for _, opt := range nlms {
			if err := o.sock.SetsockoptInt(unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, opt); err != nil {
				return err
			}
		}
		return nil
	})
}
