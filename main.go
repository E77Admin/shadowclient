package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"shadowclient/shadowproxy"

	"os"
	"os/signal"
	"time"
)

const (
	version5 uint8 = 0x05
	reserve  uint8 = 0x00
	// auth
	notRequired uint8 = 0x00
	// cmd
	connect uint8 = 0x01
	// address
	ipv4 uint8 = 0x01
	fqdn uint8 = 0x03
	ipv6 uint8 = 0x04
	// reply
	succeeded   uint8 = 0x00
	connRefused uint8 = 0x05
)

var (
	success    = []byte{version5, succeeded, reserve, ipv4, 0, 0, 0, 0, 0, 0}
	connRefuse = []byte{version5, connRefused, reserve, ipv4, 0, 0, 0, 0, 0, 0}
)

type EttConn struct {
	net.Conn
}

func (d *EttConn) Read(p []byte) (n int, err error) {
	_ = d.Conn.SetReadDeadline(time.Now().Add(time.Minute))
	return d.Conn.Read(p)
}

func (d *EttConn) Write(p []byte) (n int, err error) {
	_ = d.Conn.SetWriteDeadline(time.Now().Add(time.Minute))
	return d.Conn.Write(p)
}

func main() {
	var (
		localAddr    string
		remoteWs     string
		remoteOrigin string
		password     string
		cookie       string
	)
	flag.StringVar(&localAddr, "l", "", "local socks bind address: 127.0.0.1:1080")
	flag.StringVar(&remoteWs, "r", "", "server websocket address: ws://xxxxxxxxx")
	flag.StringVar(&remoteOrigin, "o", "", "server origin address: http://127.0.0.1:8080/")
	flag.StringVar(&password, "p", "", "password")
	flag.StringVar(&cookie, "c", "", "cookie")
	flag.Parse()

	if localAddr == "" || remoteWs == "" || password == "" || remoteOrigin == "" {
		flag.Usage()
		return
	}

	tlsConfig := tls.Config{InsecureSkipVerify: true}
	// connect quic-socks server
	client, err := shadowproxy.NewClient(remoteWs, remoteOrigin, &tlsConfig, password, cookie)
	if err != nil {
		log.Fatalln("connect ws server failed:", err)
	}

	defer client.Close()

	// accept client conn
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatal(err)
	}

	// handle signal
	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Kill, os.Interrupt)
		<-signalChan
		_ = listener.Close()
		client.Close()
	}()

	// handle conn
	tempDelay := time.Duration(0)
	max := 1 * time.Second

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > max {
					tempDelay = max
				}
				log.Printf("accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			log.Fatal(err)
		}
		tempDelay = 0
		//log.Println(conn.RemoteAddr(), "...........")
		go handleConn(client, conn)
	}
}

func handleConn(client *shadowproxy.Client, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("panic:", r)
		}
		_ = conn.Close()
	}()

	dConn := &EttConn{Conn: conn}

	// read version & authentication methods number
	buffer := make([]byte, 16)
	_, err := io.ReadFull(dConn, buffer[:2])
	if err != nil {
		log.Println("read socks5 version failed:", err)
		return
	}
	if buffer[0] != version5 {
		log.Printf("unexpected protocol version %d\n", buffer[0])
		return
	}
	authNum := int64(buffer[1])
	if authNum == 0 {
		log.Println("authentication methods number is 0")
		return
	}

	// read authentication methods(discard)
	_, err = io.Copy(ioutil.Discard, io.LimitReader(dConn, authNum))
	if err != nil {
		log.Println("read authentication methods failed:", err)
		return
	}

	// write not require
	_, err = dConn.Write([]byte{version5, notRequired})
	if err != nil {
		log.Println("write not require failed:", err)
		return
	}

	// receive connect target
	// version | cmd | reserve | address type
	_, err = io.ReadAtLeast(dConn, buffer[:4], 4)
	if err != nil {
		log.Println("receive connect target failed:", err)
		return
	}
	if buffer[0] != version5 {
		log.Printf("unexpected protocol version %d\n", buffer[0])
		return
	}
	if buffer[1] != connect {
		log.Printf("unsupport cmd %d\n", buffer[1])
		return
	}
	// buffer[2] is reserve

	// read address
	var host string
	switch buffer[3] {
	case ipv4:
		_, err = io.ReadAtLeast(dConn, buffer[:net.IPv4len], net.IPv4len)
		if err != nil {
			log.Println("read IPv4 failed:", err)
			return
		}
		host = net.IP(buffer[:4]).String()
	case ipv6:
		_, err = io.ReadAtLeast(dConn, buffer[:net.IPv6len], net.IPv6len)
		if err != nil {
			log.Println("read IPv6 failed:", err)
			return
		}
		host = "[" + net.IP(buffer[:net.IPv6len]).String() + "]"
	case fqdn:
		// get FQDN length
		_, err = io.ReadAtLeast(dConn, buffer[:1], 1)
		if err != nil {
			log.Println("read FQDN length failed:", err)
			return
		}
		l := int(buffer[0])
		if l > len(buffer) {
			buffer = make([]byte, l)
		}
		_, err = io.ReadAtLeast(dConn, buffer[:l], l)
		if err != nil {
			log.Println("read FQDN failed:", err)
			return
		}
		host = string(buffer[:l])
	default:
		log.Printf("address type not supported %d\n", buffer[0])
		return
	}

	// read port
	_, err = io.ReadAtLeast(dConn, buffer[:2], 2)
	if err != nil {
		log.Println("read port failed:", err)
		return
	}

	// start connect to quic-socks server
	port := binary.BigEndian.Uint16(buffer[:2])
	log.Println(host, port, "..............")
	socksConn, err := client.Connect(host, port)
	if err != nil {
		log.Println("ws socks:", err)
		_, _ = dConn.Write(connRefuse)
		return
	}
	defer func() { _ = socksConn.Close() }()

	// write reply
	// padding ipv4 + 0.0.0.0 + 0(port)
	_, err = dConn.Write(success)
	if err != nil {
		log.Println("write reply failed:", err)
		return
	}
	// copy
	go func() { _, _ = io.Copy(conn, socksConn) }()
	_, _ = io.Copy(socksConn, conn)
}
