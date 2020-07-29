package shadowproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"golang.org/x/net/websocket"
	"net"
)

type Client struct {
	address   string
	origin    string
	cookie    string
	password  []byte
	tlsConfig *tls.Config
	ws        *websocket.Conn
}

func NewClient(address string, origin string, tlsConf *tls.Config, password string, cookie string) (*Client, error) {
	if len(password) > 32 {
		return nil, errors.New("password size > 32")
	}
	return &Client{
		address:   address,
		origin:    origin,
		password:  []byte(password),
		tlsConfig: tlsConf,
		cookie:    cookie,
	}, nil
}

func Dial(url_, protocol, origin, cookie string) (ws *websocket.Conn, err error) {
	config, err := websocket.NewConfig(url_, origin)
	if err != nil {
		return nil, err
	}
	if protocol != "" {
		config.Protocol = []string{protocol}
	}

	config.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	config.Header.Add("Cookie", cookie)

	return websocket.DialConfig(config)
}

func (c *Client) Close() {
	if c.ws != nil {
		_ = c.ws.Close()
	}
}

func (c *Client) Connect(host string, port uint16) (net.Conn, error) {
	ws, err := Dial(c.address, "", c.origin, c.cookie)
	if err != nil {
		panic(err)
	}

	conn := tls.Client(ws, c.tlsConfig)
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("Error from client handshake: %v", err)
	}

	str := EttConn{ws: conn}
	hostData, err := packHostData(host, port)
	if err != nil {
		_ = ws.Close()
		return nil, err
	}
	// send request
	_, err = str.Write(append(c.password, hostData...))
	if err != nil {
		_ = ws.Close()
		return nil, err
	}

	// receive response
	resp := make([]byte, respSize)
	_, err = str.Read(resp)
	if err != nil {
		_ = ws.Close()
		return nil, err
	}
	if resp[0] != respOK {
		_ = ws.Close()
		return nil, Response(resp[0])
	}
	return conn, nil
}
