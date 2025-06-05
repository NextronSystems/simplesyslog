package simplesyslog

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// connWriter is used to write to the connection.
type ConnectionWriter interface {
	// WriteString writes a string to the connection. If contentType is set, it will be
	// used as the Content-Type header for HTTP(S) connections.
	WriteString(s string, contentType string) (int, error)
	// SourceIP returns the source IP of the connection.
	SourceIP() (net.IP, error)
	// Exceeds checks if the number of bytes written exceeds the specified byte limit.
	Exceeds(byteLimit int64) bool
	// Close closes the connection gracefully.
	Close() error
}

func NewConnectionWriter(connectionType ConnectionType, address string, tlsconfig *tls.Config) (ConnectionWriter, error) {
	// Validate data
	switch connectionType {
	case ConnectionUDP, ConnectionTCP, ConnectionTLS, ConnectionHTTP:
	default:
		return nil, fmt.Errorf("unknown connection type '%s'", connectionType)
	}
	if connectionType == ConnectionHTTP {
		defaultTransport, isTransport := http.DefaultTransport.(*http.Transport)
		if !isTransport {
			panic("DefaultTransport is not of type *http.Transport")
		}
		transport := defaultTransport
		if tlsconfig != nil {
			transport = defaultTransport.Clone()
			transport.TLSClientConfig = tlsconfig
		}
		return &httpWriter{
			httpURL: address,
			client:  http.Client{Transport: transport},
		}, nil
	}

	var conn net.Conn
	var err error
	// connect via udp / tcp / tls
	if connectionType == ConnectionTLS {
		conn, err = tls.Dial(string(ConnectionTCP), address, tlsconfig)
	} else {
		conn, err = net.Dial(string(connectionType), address)
	}
	if err != nil {
		return nil, err
	}
	return &basicWriter{conn: conn}, nil
}

type httpWriter struct {
	httpURL      string
	client       http.Client
	bytesWritten int64 // Number of bytes written
}

// WriteString writes a string to the connection.
func (h *httpWriter) WriteString(s string, contentType string) (int, error) {
	// No trailing newline in HTTP message body
	s = strings.TrimRight(s, "\n")
	// Send the message via HTTP(S)
	if contentType == "" {
		contentType = "text/plain"
	}
	resp, err := h.client.Post(h.httpURL, contentType, strings.NewReader(s))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("HTTP request to write the message failed with status code %d", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()
	h.bytesWritten += int64(len(s))
	return len(s), nil
}

func (h *httpWriter) Exceeds(byteLimit int64) bool {
	return h.bytesWritten > byteLimit
}

func (h *httpWriter) Close() error {
	h.client.CloseIdleConnections()
	return nil
}

func (h *httpWriter) SourceIP() (net.IP, error) {
	var addr string
	url, err := url.Parse(h.httpURL)
	if err != nil || url.Host == "" {
		return net.IP{}, fmt.Errorf("could not determine host from URL '%s'", h.httpURL)
	}
	addr = url.Host
	if url.Port() == "" {
		addr += ":80"
	}
	// Create a temporary, non-physical connection to determine the local IP (no handshake in UDP)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return net.IP{}, fmt.Errorf("could not create logical connection to determine local IP: %w", err)
	}
	defer func() { _ = conn.Close() }()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return net.IP{}, fmt.Errorf("could not determine local IP from connection: %s", conn.LocalAddr().String())
	}
	return localAddr.IP, nil
}

// basicWriter writes messages to a TCP/UDP connection.
type basicWriter struct {
	conn         net.Conn
	bytesWritten int64 // Number of bytes written
}

// WriteString writes a string to the connection.
func (b *basicWriter) WriteString(s string, contentType string) (int, error) {
	// While a terminating line break is not required in the RFC, it is "informal standard",
	// especially for data streams like TCP where we don't have the "one message per datagram" concept.
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	// Send the message via TCP/UDP
	n, err := fmt.Fprint(b.conn, s)
	b.bytesWritten += int64(n)
	return n, err
}

func (b *basicWriter) SourceIP() (net.IP, error) {
	switch addr := b.conn.LocalAddr().(type) {
	case *net.TCPAddr:
		return addr.IP, nil
	case *net.UDPAddr:
		return addr.IP, nil
	default:
		return net.IP{}, fmt.Errorf("could not determine local IP from connection: %s", b.conn.LocalAddr().String())
	}
}

func (b *basicWriter) Exceeds(byteLimit int64) bool {
	return b.bytesWritten > byteLimit
}

func (b *basicWriter) Close() error {
	return b.conn.Close()
}
