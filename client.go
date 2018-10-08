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

	/* Пробуем записать и прочитать пока не прочтем или не кончится количество попыток  */
	var n int
	for i := 0; i < retries; i++ {
		if err = conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			err = fmt.Errorf("conn.SetWriteDeadline: %v", err)
			continue
		}
		if _, err = conn.Write(packetBytes); err != nil {
			err = fmt.Errorf("conn.Write: %v", err)
			continue
		}
		if err = conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			err = fmt.Errorf("conn.SetReadDeadline: %v", err)
			continue
		}

		if n, err = conn.Read(buf[:]); err == nil {
			bytes = buf[:n]
			break
		} else {
			err = fmt.Errorf("conn.Read: %v", err)
		}

	}

	conn.Close()
	return
}
