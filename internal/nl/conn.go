package nl

import (
	"github.com/mdlayher/socket"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type Conn struct {
	*socket.Conn
}

// TryRecv - waiting until socket is ready to read.
func (c *Conn) TryRecv(p []byte, timeout *unix.Timeval) (n int, err error) {
	err = c.timeoutRcv(timeout, func(size int) error {
		n, err = c.Read(p)
		return err
	})
	return n, err
}

func (c *Conn) timeoutRcv(timeout *unix.Timeval, read func(size int) error) (err error) {
	var r unix.FdSet

	rawConn, err := c.SyscallConn()
	if err != nil {
		return errors.WithMessage(err, "failed to get raw connection")
	}

	var fd int
	err = rawConn.Control(func(fdc uintptr) {
		fd = int(fdc)
	})

	if err != nil {
		return errors.WithMessage(err, "failed to get file descriptor")
	}

	r.Zero()
	r.Set(fd)

	n, err := unix.Select(fd+1, &r, nil, nil, timeout)
	if err != nil {
		//can't waited socket (unix.EINTR)
		return err
	}

	if n == 0 {
		//Time elapsed
		return ErrNlDataNotReady
	}
	if !r.IsSet(fd) {
		//still not ready
		return ErrNlDataNotReady
	}
	if read != nil {
		err = read(n)
	}
	return err
}
