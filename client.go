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
	"os"
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

	connWriter ConnectionWriter // Writer with a connection to the syslog server
	maxBytes   int64
}

// NewClient initializes a new server connection.
// Examples:
//   - NewClient(ConnectionUDP, "172.0.0.1:514")
//   - NewClient(ConnectionTCP, ":514")
//   - NewClient(ConnectionTLS, "172.0.0.1:514")
//   - NewClient(ConnectionHTTP, "https://example.com:8080/syslog")
func NewClient(connectionType ConnectionType, address string, tlsconfig *tls.Config) (*Client, error) {
	connWriter, err := NewConnectionWriter(connectionType, address, tlsconfig)
	if err != nil {
		return nil, fmt.Errorf("could not create connection writer: %w", err)
	}
	// get hostname and ip of system
	hostname, err := os.Hostname()
	if err != nil {
		hostname = DefaultHostname
	}
	ip := DefaultIP
	if netIP, err := connWriter.SourceIP(); err == nil {
		ip = netIP.String()
	}
	// return the server
	return &Client{
		Hostname:   hostname,
		IP:         ip,
		connWriter: connWriter,
	}, nil
}

// ErrTooManyBytesSent will be returned, if a message could not be sent
// because of a hard limit of bytes to be sent.
var ErrTooManyBytesSent = errors.New("too many bytes sent")

// Send sends a syslog message with a specified priority. It adds a syslog header with timestamp, hostname and priority.
// Examples:
//   - Send("foo", LOG_LOCAL0|LOG_NOTICE)
//   - Send("bar", LOG_DAEMON|LOG_DEBUG)
func (client *Client) Send(message string, priority Priority) error {
	return client.SendMasked(message, priority, "")
}

// SendMasked sends a syslog message with a specified priority. It adds a syslog header
// with timestamp, hostname and priority. If maskedHostname is provided, it will be used
// instead of the hostname/IP combination.
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

	var hostnameCombi string
	switch {
	case maskedHostname != "":
		// Use masked hostname if provided (without an additional IP, i.e., ignore HostnameOnly)
		hostnameCombi = maskedHostname
	case !client.HostnameOnly:
		// Use hostname and IP if HostnameOnly is false
		hostnameCombi = fmt.Sprintf("%s/%s", client.Hostname, client.IP)
	default:
		// Fallback to hostname only
		hostnameCombi = client.Hostname
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
