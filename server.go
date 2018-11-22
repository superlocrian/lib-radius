package radius

import (
	"errors"
	l "github.com/sirupsen/logrus"
	"net"
	"time"
)

type Request struct {
	Start time.Time
	Secret     []byte
	RemoteAddr *net.UDPAddr
	Packet     *Packet
	//deprecated
	// нужен для того чтобы, по мере прохождения запроса через бизнес логику,
	// сохранять попутнуб информация типо полей для сквозного логирования etc ...
	Context interface{}
}
type Handler interface {
	ServeRequest(*net.UDPConn, *Request)
}

type HandlerFunc func(*net.UDPConn, *Request)

func (f HandlerFunc) ServeRequest(conn *net.UDPConn, r *Request) {
	f(conn, r)
}

/**
Example server
 */
type Server struct {
	Start time.Time
	// Address to bind the server on. If empty, the address defaults to ":1812".
	Addr string
	// Network of the server. Valid values are "udp", "udp4", "udp6". If empty,
	// the network defaults to "udp".
	Network string
	// Listener
	connection *net.UDPConn

	Handler Handler
}

// ListenAndServe starts a RADIUS server on the address given in s.
func (s *Server) ListenAndServe() error {
	s.Start = time.Now()
	var (
		err  error
		addr *net.UDPAddr
	)
	if s.connection != nil {
		return errors.New("radius: server already started")
	}

	if s.Handler == nil {
		return errors.New("radius: nil Handler")
	}

	addrStr := ":1812"
	if s.Addr != "" {
		addrStr = s.Addr
	}
	if s.Network == "" {
		s.Network = "udp"
	}
	if addr, err = net.ResolveUDPAddr(s.Network, addrStr); err != nil {
		return err
	}
	if s.connection, err = net.ListenUDP(s.Network, addr); err != nil {
		return err
	}
	defer s.connection.Close()

	s.connection.SetReadBuffer(4194304)
	s.connection.SetWriteBuffer(4194304)

	var n int
	for {

		//new request
		r := &Request{
			Start:time.Now(),
			Packet: &Packet{},
		}
		buff := make([]byte, MaxPacketLength)
		n, r.RemoteAddr, err = s.connection.ReadFromUDP(buff)
		if err != nil && !err.(*net.OpError).Temporary() {
			break
		}
		if n == 0 {
			continue
		}
		r.Packet.Wire = buff[:n]

		//try decode and check
		if err := r.Packet.Decode(); err != nil {
			l.Errorf(" packet decode: %v wire: %x", err, r.Packet.Wire)
			continue
		}
		//todo  goroutine counting
		go s.Handler.ServeRequest(s.connection, r)
	}

	return nil
}

// Close stops listening for packets. Any packet that is currently being
// handled will not be able to respond to the sender.
func (s *Server) Close() error {
	if s.connection == nil {
		return nil
	}
	return s.connection.Close()
}
