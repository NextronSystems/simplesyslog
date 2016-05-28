// Simple Syslog Client
//
// Florian Roth
// March 2016

package simplesyslog

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// SyslogServer defines a syslog server IP and server port
type SyslogServer struct {
	ServerIP   string
	ServerPort int
	udpConn    *net.UDPConn
	isActive   bool
	hostname   string
	hostip     string
	Rfc3164    bool
	Rfc5424    bool
}

// initialize Syslog connection
func (ss *SyslogServer) Initialize() (bool, string) {
	// Preset
	ss.isActive = false

	// Server Target
	var serverSocket = fmt.Sprintf("%s:%d", ss.ServerIP, ss.ServerPort)
	ServerAddr, err := net.ResolveUDPAddr("udp", serverSocket)
	if err != nil {
		return false, "Cannot resolve target address"
	}
	// Connect
	var con_err error
	ss.udpConn, con_err = net.DialUDP("udp", nil, ServerAddr)
	if con_err != nil {
		return false, "Cannot connect to target system"
	}

	// Hostname and Local IP address
	var err_hn error
	ss.hostname, err_hn = os.Hostname()
	if err_hn != nil {
		ss.hostname = "unknown"
	}
	ss.hostip = strings.Split(fmt.Sprintf("%v", ss.udpConn.LocalAddr()), ":")[0]

	// Everything went fine
	ss.isActive = true
	return true, "Connection succeeded"
}

// Send allows to send a syslog message to the set server and port
func (ss *SyslogServer) Send(message string, facility string, severity string) {
	var f = facilities[facility]
	var s = severities[severity]

	// Prepare Header
	pri := (f * 8) + s
	timestamp := time.Now().Format("Jan _2 15:04:05")
	hostnameCombi := fmt.Sprintf("%s/%s", ss.hostname, ss.hostip)
	header := fmt.Sprintf("<%d>%s %s", pri, timestamp, hostnameCombi)

	// RFC length reduction
	if ss.Rfc3164 && len(message) > 1024 {
		message = fmt.Sprintf("%s...", message[:1020])
	}
	if ss.Rfc5424 && len(message) > 2048 {
		message = fmt.Sprintf("%s...", message[:2044])
	}

	// Full Message
	full_message := fmt.Sprintf("%s %s", header, message)

	// fmt.Println(full_message)
	fmt.Fprintf(ss.udpConn, full_message)
}

// Terminate closes the connection gracefully
func (ss *SyslogServer) Terminate() {
	ss.udpConn.Close()
}

// Syslog severities
// See https://www.ietf.org/rfc/rfc3164.txt
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
// See https://www.ietf.org/rfc/rfc3164.txt
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
