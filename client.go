// Simple Syslog Server that
// supports UDP, TCP and TLS.
//
// Marcel Gebhardt
// April 2018

package simplesyslog

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ConnectionType defines wheather to connect via UDP or TCP (or TLS)
type ConnectionType string

const (
	// ConnectionUDP connects via UDP
	ConnectionUDP ConnectionType = "udp"
	// ConnectionTCP connects via TCP
	ConnectionTCP ConnectionType = "tcp"
	// ConnectionTLS connects via TLS
	ConnectionTLS ConnectionType = "tls"
	// ConnectionHTTP connects via HTTP(S)
	ConnectionHTTP ConnectionType = "http"
)

const (
	// DefaultHostname will be used if hostname could not be determined
	DefaultHostname string = "unknown"
	// DefaultIP will be used if host address could not be determined
	DefaultIP string = ""
)

const (
	Rfc3164   = 1024
	Rfc5424   = 2048
	Unlimited = 0
)

// Client holds a connection to a specified address
type Client struct {
	Hostname     string // Hostname of the system
	IP           string // IP of the system
	Rfc3339      bool   // use rfc3339 instead of stamp for time format
	MaxLength    int    // max syslog length
	NoPrio       bool   // do not add <prio> Prefix
	HostnameOnly bool   // Only use hostname in syslog header instead of hostname/IP combination

	connWriter connectionWriter // Writer with a connection to the syslog server
	maxBytes   int64
}

// connWriter is used to write to the connection.
type connectionWriter struct {
	httpURL     string      // HTTP(S) URL. If empty, a non-HTTP connection is used.
	client      http.Client // Connection client if HTTP(S)

	conn net.Conn // Connection if not HTTP(S)

	bytesWritten int64 // Number of bytes written
}

// WriteString writes a string to the connection.
func (c *connectionWriter) WriteString(s string, contentType string) (int, error) {
	// While a terminating line break is not required in the RFC, it is "informal standard",
	// especially for data streams like TCP where we don't have the "one message per datagram" concept.
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	if c.httpURL != "" {
		// Send the message via HTTP(S)
		if contentType == "" {
			contentType = "text/plain"
		}
		resp, err := c.client.Post(c.httpURL, contentType, strings.NewReader(s))
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		c.bytesWritten += int64(len(s))
		return len(s), nil
	} else {
		// Send the message via TCP/UDP
		n, err := fmt.Fprint(c.conn, s)
		c.bytesWritten += int64(n)
		return n, err
	}
}

func (c *connectionWriter) Exceeds(byteLimit int64) bool {
	return c.bytesWritten > byteLimit
}

func (c *connectionWriter) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// NewClient initializes a new server connection.
// Examples:
//   - NewClient(ConnectionUDP, "172.0.0.1:514")
//   - NewClient(ConnectionTCP, ":514")
//   - NewClient(ConnectionTLS, "172.0.0.1:514")
//   - NewClient(ConnectionHTTP, "https://example.com:8080/syslog")
func NewClient(connectionType ConnectionType, address string, tlsconfig *tls.Config) (*Client, error) {
	// Validate data
	if connectionType != ConnectionUDP && connectionType != ConnectionTCP && connectionType != ConnectionTLS && connectionType != ConnectionHTTP {
		return nil, fmt.Errorf("unknown connection type '%s'", connectionType)
	}
	var (
		connWriter connectionWriter
		err        error
	)
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
		connWriter = connectionWriter{
			httpURL:     address,
			client:      http.Client{Transport: transport},
		}
	} else {
		var conn net.Conn
		// connect via udp / tcp / tls
		if connectionType == ConnectionTLS {
			conn, err = tls.Dial(string(ConnectionTCP), address, tlsconfig)
		} else {
			conn, err = net.Dial(string(connectionType), address)
		}
		if err != nil {
			return nil, err
		}
		connWriter = connectionWriter{conn: conn}
	}
	// get hostname and ip of system
	hostname, err := os.Hostname()
	if err != nil {
		hostname = DefaultHostname
	}
	ip, err := getLocalIP(connWriter.conn)
	if err != nil {
		ip = DefaultIP
	}
	// return the server
	return &Client{
		Hostname:   hostname,
		IP:         ip,
		connWriter: connWriter,
	}, nil
}

func getLocalIP(conn net.Conn) (string, error) {
	if conn == nil {
		// Create a temporary, non-physical connection to determine the local IP (no handshake in UDP)
		var err error
		conn, err = net.Dial("udp", "8.8.8.8:80")
		if err != nil {
			return "", fmt.Errorf("could not create logical connection to determine local IP: %w", err)
		}
		defer func() { _ = conn.Close() }()
	}
	ip, _, err := net.SplitHostPort(conn.LocalAddr().String())
	return ip, err
}

// ErrTooManyBytesSent will be returned, if a message could not be sent
// because of a hard limit of bytes to be send.
var ErrTooManyBytesSent = errors.New("too many bytes sent")

// Send sends a syslog message with a specified priority. It adds a syslog header with timestamp, hostname and priority.
// Examples:
//   - Send("foo", LOG_LOCAL0|LOG_NOTICE)
//   - Send("bar", LOG_DAEMON|LOG_DEBUG)
func (client *Client) Send(message string, priority Priority) error {
	return client.SendMasked(message, priority, "")
}

// SendMasked sends a syslog message with a specified priority. It adds a syslog header with timestamp, hostname and priority. If maskedHostname is provided, it will be used instead of the hostname/IP combination.
// Examples:
//   - Send("foo", LOG_LOCAL0|LOG_NOTICE, "")
//   - Send("bar", LOG_DAEMON|LOG_DEBUG, "myhost")
func (client *Client) SendMasked(message string, priority Priority, maskedHostname string) error {
	if client.maxBytes != 0 && client.connWriter.Exceeds(client.maxBytes) {
		return ErrTooManyBytesSent
	}
	var timestamp string
	if client.Rfc3339 {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	} else {
		timestamp = time.Now().UTC().Format(time.Stamp)
	}
	var hostnameCombi = client.Hostname
	if maskedHostname == "" {
		if !client.HostnameOnly {
			hostnameCombi = fmt.Sprintf("%s/%s", hostnameCombi, client.IP)
		}
	} else {
		// Use masked hostname if provided (without an additional IP, i.e., ignore HostnameOnly)
		hostnameCombi = maskedHostname
	}
	var header string
	if client.NoPrio {
		header = fmt.Sprintf("%s %s", timestamp, hostnameCombi)
	} else {
		header = fmt.Sprintf("<%d>%s %s", int(priority), timestamp, hostnameCombi)
	}
	// RFC length reduction
	length := len(message)
	if client.MaxLength > 3 && length > client.MaxLength {
		message = fmt.Sprintf("%s...", message[:client.MaxLength-3])
	}
	outMsg := fmt.Sprintf("%s %s", header, message)
	return client.sendRaw(outMsg, "")
}

// SendJSON sends a syslog message as a JSON message if applicable, i.e., if connection type is HTTP(S) Content-Type is set accordingly. Note: message should be valid JSON. No syslog header is added and a check for MaxLength is not applied here.
// Examples:
//   - SendRaw("foo")
//   - SendRaw("bar")
func (client *Client) SendJSON(message string) error {
	return client.sendRaw(message, "application/json")
}

// SendRaw sends a syslog message without adding syslog header. Note: a check for MaxLength is not applied here.
// Examples:
//   - SendRaw("foo")
//   - SendRaw("bar")
func (client *Client) SendRaw(message string) error {
	return client.sendRaw(message, "")
}

// sendRaw sends a raw syslog message without adding a syslog header. If contentType is set, it will be used as the Content-Type header for HTTP(S) connections. Note: a check for MaxLength is not applied here.
func (client *Client) sendRaw(message string, contentType string) error {
	if client.maxBytes != 0 && client.connWriter.Exceeds(client.maxBytes) {
		return ErrTooManyBytesSent
	}
	// Send message
	_, err := client.connWriter.WriteString(message, contentType)
	return err
}

// Close closes the server connection gracefully.
func (client *Client) Close() error {
	return client.connWriter.Close()
}

// SetMaxBytes sets the maximum bytes that will be sent to rsyslog
func (client *Client) SetMaxBytes(i int64) {
	client.maxBytes = i
}
