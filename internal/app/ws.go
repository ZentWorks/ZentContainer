package app

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type wsConn struct {
	conn net.Conn
	rw   *bufio.ReadWriter
	mu   sync.Mutex
}

func acceptWS(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if r.Header.Get("X-ZC-Proxy") != "controller" {
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				return nil, errors.New("websocket origin rejected")
			}
		}
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("websocket upgrade required")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing websocket key")
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijacking unsupported")
	}
	conn, rw, err := h.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
	if err == nil {
		err = rw.Flush()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, rw: rw}, nil
}
func (w *wsConn) Close() error { return w.conn.Close() }
func (w *wsConn) WriteFrame(op byte, p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	hdr := []byte{0x80 | op}
	n := len(p)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 65535:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127, 0, 0, 0, 0, byte(uint64(n)>>24), byte(uint64(n)>>16), byte(uint64(n)>>8), byte(n))
	}
	if _, err := w.rw.Write(hdr); err != nil {
		return err
	}
	if _, err := w.rw.Write(p); err != nil {
		return err
	}
	return w.rw.Flush()
}
func (w *wsConn) ReadFrame() (byte, []byte, error) {
	b1, err := w.rw.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	b2, err := w.rw.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	op := b1 & 0x0f
	masked := b2&0x80 != 0
	n := uint64(b2 & 0x7f)
	if n == 126 {
		var x uint16
		if err := binary.Read(w.rw, binary.BigEndian, &x); err != nil {
			return 0, nil, err
		}
		n = uint64(x)
	} else if n == 127 {
		if err := binary.Read(w.rw, binary.BigEndian, &n); err != nil {
			return 0, nil, err
		}
	}
	if n > 8*1024*1024 {
		return 0, nil, errors.New("websocket frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.rw, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	p := make([]byte, int(n))
	if _, err := io.ReadFull(w.rw, p); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range p {
			p[i] ^= mask[i%4]
		}
	}
	return op, p, nil
}
