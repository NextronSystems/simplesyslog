// Simple Syslog Server that
// supports UDP, TCP and TLS.
//
// Marcel Gebhardt
// April 2018

package simplesyslog

import (
	"crypto/tls"
	"fmt"
	"net"
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
)

const (
	// DefaultHostname will be used if hostname could not be determined
	DefaultHostname string = "unknown"
	// DefaultIP will be used if ip could not be determined
	DefaultIP string = ""
)

// Client holds a connection to a specified address
type Client struct {
	Hostname string   // Hostname of the system
	IP       string   // IP of the system
	Rfc3164  bool     // rfc standard for length reduction
	Rfc5424  bool     // rfc standard for length reduction
	conn     net.Conn // connection to the syslog server
}

// NewClient initializes a new server connection.
// Examples:
//   - NewClient(ConnectionUDP, "172.0.0.1:514")
//   - NewClient(ConnectionTCP, ":514")
//   - NewClient(ConnectionTLS, "172.0.0.1:514")
func NewClient(connectionType ConnectionType, address string) (*Client, error) {
	// Validate data
	if connectionType != ConnectionUDP && connectionType != ConnectionTCP && connectionType != ConnectionTLS {
		return nil, fmt.Errorf("unknown connection type '%s'", connectionType)
	}
	var (
		conn net.Conn
		err  error
	)
	// connect via udp / tcp / tls
	if connectionType == ConnectionTLS {
		conn, err = tls.Dial(string(ConnectionTCP), address, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.Dial(string(connectionType), address)
	}
	if err != nil {
		return nil, err
	}
	// get hostname and ip of system
	hostname, err := os.Hostname()
	if err != nil {
		hostname = DefaultHostname
	}
	ip, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		ip = DefaultIP
	}
	// return the server
	return &Client{
		Hostname: hostname,
		IP:       ip,
		conn:     conn,
	}, nil
}

// Send sends a syslog message with a specified priority.
// Examples:
//   - Send("foo", LOG_LOCAL0|LOG_NOTICE)
//   - Send("bar", LOG_DAEMON|LOG_DEBUG)
func (client *Client) Send(message string, priority Priority) error {
	timestamp := time.Now().Format("Jan _2 15:04:05")
	hostnameCombi := fmt.Sprintf("%s/%s", client.Hostname, client.IP)
	header := fmt.Sprintf("<%d>%s %s", int(priority), timestamp, hostnameCombi)
	// RFC length reduction
	if client.Rfc3164 && len(message) > 1024 {
		message = fmt.Sprintf("%s...", message[:1020])
	}
	if client.Rfc5424 && len(message) > 2048 {
		message = fmt.Sprintf("%s...", message[:2044])
	}
	// Send message
	_, err := fmt.Fprintf(client.conn, "%s %s", header, message)
	return err
}

// Close closes the server connection gracefully.
func (client *Client) Close() error {
	return client.conn.Close()
}
