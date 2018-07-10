package radius

import (
	"fmt"
	"net"
	"time"
)

func Exchange(packetBytes []byte, dst *net.UDPAddr, src *net.UDPAddr, retries int, timeout time.Duration) (bytes []byte, err error) {
	var (
		conn *net.UDPConn
		buf  [MaxPacketLength]byte
	)

	if conn, err = net.DialUDP("udp4", src, dst); err != nil {
		err = fmt.Errorf("net.DialUDP: %v", err)
		return
	}

	for i := 0; i < retries; i++ {
		if err = conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			err = fmt.Errorf("conn.SetWriteDeadline: %v", err)
			break
		}
		if _, err = conn.Write(packetBytes); err != nil {
			err = fmt.Errorf("conn.Write: %v", err)
			break
		}
		if err = conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			err = fmt.Errorf("conn.SetReadDeadline: %v", err)
			break
		}
		if _, err = conn.Read(buf[:]); err != nil {
			err = fmt.Errorf("conn.Read: %v", err)
			break
		}
		bytes = buf[:]
	}

	conn.Close()
	return
}
