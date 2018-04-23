package simplesyslog

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"
)

const host = "127.0.0.1:15140"

const tlsCRT = `-----BEGIN CERTIFICATE-----
MIICJzCCAZACCQCPGY+4vjNV0TANBgkqhkiG9w0BAQUFADBYMQswCQYDVQQGEwJE
RTEPMA0GA1UECAwGSGVzc2VuMRIwEAYDVQQHDAlGcmFua2Z1cnQxEjAQBgNVBAoM
CUNvZGVoYXJkdDEQMA4GA1UEAwwHVGVzdGluZzAeFw0xODA0MjAwNzUwMzZaFw0x
OTA0MjEwNzUwMzZaMFgxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZIZXNzZW4xEjAQ
BgNVBAcMCUZyYW5rZnVydDESMBAGA1UECgwJQ29kZWhhcmR0MRAwDgYDVQQDDAdU
ZXN0aW5nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcHWCPUdd4VfxorTjk
5g/97HiAdcVn2kbDEVv2aI9HdSbcC9DC209DoaX4/7+3cEf3TwE5RKu9acf8tDue
W8tAWvKH4wW7hIHiipfhFisuQeLe5NgXGqY+bs+B5+A0C/rKTrGkHu8hpXjFPY2y
rwyYMBPmIm44X53tzsNYzuQakQIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAL5k/7HU
g2+6QcrV2K+2616D0ssgFrKqyG1dTy9w2+jZPQWcVNTRXGDkfdK/JlXzfEQwI/bZ
89GmxswWxoxoMi7ZMPAG2h66vMUwCFTjUGEihgX/qksnzglMTQHlgLGENfQfawy1
G1MpWJaW2ClQGr70dTTFeFJLSOANdAEqkTOC
-----END CERTIFICATE-----`

const tlsKEY = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDcHWCPUdd4VfxorTjk5g/97HiAdcVn2kbDEVv2aI9HdSbcC9DC
209DoaX4/7+3cEf3TwE5RKu9acf8tDueW8tAWvKH4wW7hIHiipfhFisuQeLe5NgX
GqY+bs+B5+A0C/rKTrGkHu8hpXjFPY2yrwyYMBPmIm44X53tzsNYzuQakQIDAQAB
AoGBAI8JmCIKcRcF6YysZHh6+JFuBbCU179xHOLOeRBbSiCJhMMh+ntlwNCWTyDM
MW2nTVzsvkLU2TWxdABHryZtSFpJIq69euzRtEN3uFy5qJWGvlE6Tn+ps7XIbPsX
rppeclgV7a2nznrh+v1hfY/hgePyhuDsH0Hh5HB+L/gdb5DxAkEA81IPoy/UZWKg
wIGeGy0mWyb4rmIxJTxOQPHd+2iJaD173eY0PskWuMLHFjyVn2gqHdy88ZDe0Xh9
35SjOw5J7wJBAOeVvye1hnvOdgOHpuurDwvoTy/A+hUhzuzPKyUhNwENHk1d5L8D
w2n+onITuFhRUvJW+ZCn+8BcY2Q0FNUqY38CQQCs7WhhsQ+BkqvuxPAKHneBFtxs
iyqkbQysiXkbQXtOk0viM8ZzzNSSMRPvENXBufUczhGWmUBSnRDQgsHTqd8PAkAv
Wdbz75HHzrcikaH3nco9zQoj4XlAyODeWp2fweLVPDFt8DzNMZ/LFF1ypcWTiU1E
b7Qnd7Fp63oHCv8XdstRAkEA5Lf2nA2rEi5WxvSIea5KUzQp6Ut1aCLjHpdU5Pk7
4IqCgyaC9pPvCkL6rEOthAfh9nnPJp41zMk7jHz5zmRe6g==
-----END RSA PRIVATE KEY-----`

var tlsConfig *tls.Config

var messageRegex = regexp.MustCompile(`<133>[A-Z][a-z]{2} (([0-9]{2})|( [0-9])) [0-9]{2}:[0-9]{2}:[0-9]{2} testing\/127\.0\.0\.1 foo bar baz`)

func TestNewClient(t *testing.T) {
	testNewClientTCP(t, false)
	testNewClientTCP(t, true)
	testNewClientUDP(t)
}

func testNewClientUDP(t *testing.T) {
	t.Logf("testing udp")
	serverAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		t.Fatalf("could not resolve udp addr: %s", err)
	}
	conn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("could not listen udp: %s", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second * 5)); err != nil {
		t.Fatalf("could not set read deadline: %s", err)
	}
	defer conn.Close()
	go func() {
		/*
		 * Send the message 'foo bar baz' to the syslog server
		 */
		client, err := NewClient(ConnectionUDP, host)
		if err != nil {
			t.Fatalf("could not initialize server: %s", err)
		}
		client.Hostname = "testing" // overwrite hostname for testing
		defer client.Close()
		if err := client.Send("foo bar baz", LOG_LOCAL0|LOG_NOTICE); err != nil {
			t.Fatalf("could not send message: %s", err)
		}
	}()
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("could not read udp: %s", err)
	}
	b := buf[:n]
	if !messageRegex.MatchString(string(b)) {
		t.Fatalf("wrong message: %s", string(b))
	} else {
		t.Logf("correct message: '%s'", string(b))
	}
}

func testNewClientTCP(t *testing.T, useTLS bool) {
	t.Logf("testing tcp with tls '%s'", strconv.FormatBool(useTLS))
	var (
		listener net.Listener
		err      error
	)
	if useTLS {
		listener, err = tls.Listen("tcp", host, tlsConfig)
	} else {
		listener, err = net.Listen("tcp", host)
	}
	if err != nil {
		t.Fatalf("could not listen: %s", err)
	}
	defer listener.Close()
	go func() {
		/*
		 * Send the message 'foo bar baz' to the syslog server
		 */
		connectionType := ConnectionTCP
		if useTLS {
			connectionType = ConnectionTLS
		}
		client, err := NewClient(connectionType, host)
		if err != nil {
			t.Fatalf("could not initialize server: %s", err)
		}
		client.Hostname = "testing" // overwrite hostname for testing
		defer client.Close()
		if err := client.Send("foo bar baz", LOG_LOCAL0|LOG_NOTICE); err != nil {
			t.Fatalf("could not send message: %s", err)
		}
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("could not accept connection: %s", err)
		}
		defer conn.Close()
		b, err := ioutil.ReadAll(conn)
		if err != nil {
			t.Fatalf("could not read all: %s", err)
		}
		if !messageRegex.MatchString(string(b)) {
			t.Fatalf("wrong message: %s", string(b))
		} else {
			t.Logf("correct message: '%s'", string(b))
		}
		return
	}
}

func init() {
	pemCert, _ := pem.Decode([]byte(tlsCRT))
	if pemCert == nil {
		panic("no test tls certificate")
	}
	pemKey, _ := pem.Decode([]byte(tlsKEY))
	if pemKey == nil {
		panic("no test tls key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(pemKey.Bytes)
	if err != nil {
		panic("invalid test tls key")
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{pemCert.Bytes},
		PrivateKey:  privateKey,
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS11,
	}
}
