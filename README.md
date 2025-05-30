# simplesyslog

[![Build Status](https://travis-ci.org/NextronSystems/simplesyslog.svg?branch=master)](https://travis-ci.org/NextronSystems/simplesyslog)

Simple SYSLOG client in Go

## Installation

`go get github.com/NextronSystems/simplesyslog`

## Example Usage

```go

import (
    syslog "github.com/NextronSystems/simplesyslog"
)

const SyslogServer = "<hostname>:<port>"

func main() {
    client, err := syslog.NewClient(syslog.ConnectionUDP, SyslogServer)
    if err != nil {
        ...
    }
    defer client.Close()
    if err := client.Send("foo bar baz", syslog.LOG_LOCAL0|syslog.LOG_NOTICE); err != nil {
        ...
    }
}
```
