package telnet

import (
	"bufio"
	"net"
	"time"
)

type TelnetHelper struct {
	net.Conn
	r       *bufio.Reader
	version string
}

func NewTelnetHelper(network, addr string, timeout time.Duration) (*TelnetHelper, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	tel := TelnetHelper{
		Conn:    conn,
		r:       bufio.NewReaderSize(conn, 256),
		version: "v0.1",
	}
	return &tel, nil
}

func (t *TelnetHelper) Check() (int, error) {
	// Read 2 bytes is enough to check
	buf := make([]byte, 2)
	var n int
	for n < len(buf) {
		b, retry, err := t.tryReadByte()
		if err != nil {
			return n, err
		}
		if !retry {
			buf[n] = b
			n++
		}
		if n > 0 && t.r.Buffered() == 0 {
			// Don't block if can't return more data.
			return n, err
		}
	}
	return n, nil
}

func (t *TelnetHelper) tryReadByte() (b byte, retry bool, err error) {
	b, err = t.r.ReadByte()
	if err != nil || b != cmdIAC {
		return
	}
	b, err = t.r.ReadByte()
	if err != nil {
		return
	}
	if b != cmdIAC {
		// Read an option
		o, err2 := t.r.ReadByte()
		if err2 != nil {
			err = err2
			return
		}
		// Deny any other option
		err = t.deny(b, o)
		if err != nil {
			return
		}

		retry = true
	}
	return
}

func (t *TelnetHelper) deny(cmd, opt byte) (err error) {
	switch cmd {
	case cmdDo:
		err = t.wont(opt)
	case cmdDont:
		// nop
	case cmdWill, cmdWont:
		err = t.dont(opt)
	}
	return
}

func (t *TelnetHelper) wont(option byte) error {
	_, err := t.Conn.Write([]byte{cmdIAC, cmdWont, option})
	return err
}

func (t *TelnetHelper) dont(option byte) error {
	_, err := t.Conn.Write([]byte{cmdIAC, cmdDont, option})
	return err
}

const (
	cmdWill = 251
	cmdWont = 252
	cmdDo   = 253
	cmdDont = 254

	cmdIAC = 255
)
