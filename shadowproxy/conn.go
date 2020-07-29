package shadowproxy

import (
	"net"
	"time"
)

type EttConn struct {
	ws net.Conn
}

func (d *EttConn) Read(p []byte) (n int, err error) {
	_ = d.ws.SetReadDeadline(time.Now().Add(time.Minute))
	return d.ws.Read(p)
}

func (d *EttConn) Write(p []byte) (n int, err error) {
	_ = d.ws.SetWriteDeadline(time.Now().Add(time.Minute))
	return d.ws.Write(p)
}
