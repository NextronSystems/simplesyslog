// Simple Syslog Client
//
// Florian Roth
// March 2016

package simplesyslog

import (
	"fmt"
	"net"
	"os"
	"time"
)

// SyslogServer defines a syslog server IP and server port
type SyslogServer struct {
	ServerIP   string
	ServerPort int
}

// Send allows to send a syslog message to the set server and port
func (ss SyslogServer) Send(message string, facility string, severity string) {
	var f = facilities[facility]
	var s = severities[severity]

	// Server Target
	var serverSocket = fmt.Sprintf("%s:%d", ss.ServerIP, ss.ServerPort)
	ServerAddr, err := net.ResolveUDPAddr("udp", serverSocket)
	CheckError(err)
	// Connect
	conn, err := net.DialUDP("udp", nil, ServerAddr)
	CheckError(err)
	defer conn.Close()

	// Prepare Header
	var pri = (f * 8) + s
	var timestamp = time.Now().Format(time.RFC3339)
	var hostname, _ = os.Hostname()
	var header = fmt.Sprintf("<%d>1 %s %s", pri, timestamp, hostname)

	// Full Message
	var full_message = fmt.Sprintf("%s %s", header, message)

	fmt.Println(full_message)
	fmt.Fprintf(conn, full_message)
	conn.Close()
}

// Syslog severities
// See https://tools.ietf.org/html/rfc5424
var severities = map[string]int{
	"emergency": 0,
	"alert":     1,
	"critical":  2,
	"error":     3,
	"warning":   4,
	"notice":    5,
	"info":      6,
	"debug":     7,
}

// Syslog facilities
// See https://tools.ietf.org/html/rfc5424
var facilities = map[string]int{
	"kernel":     0,
	"user-level": 1,
	"mail":       2,
	"system":     3,
	"security":   4,
	"messages":   5,
	"printer":    6,
	"news":       7,
	"uucp":       8,
	"clock":      9,
	"auth":       10,
	"ftp":        11,
	"ntp":        12,
	"audit":      13,
	"log":        14,
	"cron":       15,
	"local0":     16,
	"local1":     17,
	"local2":     18,
	"local3":     19,
	"local4":     20,
	"local5":     21,
	"local6":     22,
	"local7":     23,
}

// CheckError is a simple error checker function
func CheckError(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
	}
}
