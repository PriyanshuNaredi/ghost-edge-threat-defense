package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// wsGUID is the magic GUID from RFC 6455 section 4.2.2.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// SecurityEvent is the structured telemetry record broadcast to every dashboard.
// Wire format: [timestamp, client_ip, route, threat_type, score, action_taken].
type SecurityEvent struct {
	Timestamp string     `json:"timestamp"`
	ClientIP  string     `json:"client_ip"`
	Route     string     `json:"route"`
	Threat    ThreatType `json:"threat_type"`
	Score     float64    `json:"score"`
	Action    Action     `json:"action_taken"`
	Payload   string     `json:"payload,omitempty"`
	Conf      float64    `json:"confidence,omitempty"`
	Headers   [][2]string `json:"headers,omitempty"`
}

// wsClient is a single connected dashboard.
type wsClient struct {
	conn   net.Conn
	send   chan []byte
	closed chan struct{}
	once   sync.Once
}

// Hub fans out security events to all connected WebSocket clients.
type Hub struct {
	mu      sync.RWMutex
	clients map[*wsClient]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*wsClient]struct{})}
}

// Clients returns the number of connected dashboards.
func (h *Hub) Clients() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Broadcast serializes the event and queues it for every client.
func (h *Hub) Broadcast(ev SecurityEvent) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.send <- data:
		default: // slow client: drop rather than block the pipeline
		}
	}
}

// ServeWS performs the RFC 6455 handshake and wires the client into the hub.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		conn.Close()
		return
	}
	rw.Flush()

	c := &wsClient{conn: conn, send: make(chan []byte, 256), closed: make(chan struct{})}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()

	go c.writePump()
	go c.readPump(h)
}

// writePump frames queued messages as unmasked text frames.
func (c *wsClient) writePump() {
	defer c.conn.Close()
	for {
		select {
		case msg, ok := <-c.send:
			if !ok {
				return
			}
			if err := writeFrame(c.conn, msg); err != nil {
				return
			}
		case <-c.closed:
			return
		}
	}
}

// readPump drains client frames (ping/pong/close) so the connection stays alive.
func (c *wsClient) readPump(h *Hub) {
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
		c.once.Do(func() { close(c.closed) })
		c.conn.Close()
	}()
	br := bufio.NewReader(c.conn)
	for {
		op, payload, err := readFrame(br)
		if err != nil {
			return
		}
		switch op {
		case 0x8: // close
			return
		case 0x9: // ping -> pong
			writeControl(c.conn, 0xA, payload)
		}
	}
}

// writeFrame writes an unmasked binary/text frame (server->client frames are never masked).
func writeFrame(w io.Writer, payload []byte) error {
	n := len(payload)
	var header []byte
	opcode := byte(0x1) // text
	switch {
	case n < 126:
		header = []byte{0x80 | opcode, byte(n)}
	case n <= 0xFFFF:
		header = []byte{0x80 | opcode, 126, 0, 0}
		binary.BigEndian.PutUint16(header[2:], uint16(n))
	default:
		header = append([]byte{0x80 | opcode, 127, 0, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 0)...)
		binary.BigEndian.PutUint64(header[2:], uint64(n))
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// writeControl writes a small control frame (pong/close).
func writeControl(w io.Writer, opcode byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	header := []byte{0x80 | opcode, byte(len(payload))}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one client frame, unmasking the payload per RFC 6455.
func readFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		length = binary.BigEndian.Uint64(ext)
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(r, maskKey[:]); err != nil {
			return
		}
	}
	if length > 1<<20 { // 1 MiB sanity cap
		err = io.ErrUnexpectedEOF
		return
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return
}

// keepalive sends periodic pings so proxies and browsers don't drop idle sockets.
func (h *Hub) keepalive() {
	ticker := time.NewTicker(20 * time.Second)
	for range ticker.C {
		h.mu.RLock()
		for c := range h.clients {
			select {
			case <-c.closed:
			default:
				writeControl(c.conn, 0x9, nil)
			}
		}
		h.mu.RUnlock()
	}
}
