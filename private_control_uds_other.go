//go:build !linux

package main

import (
	"errors"
	"net"
)

func startPrivateControlUDSListener(privateControlConfig) (net.Listener, error) {
	return nil, errors.New("private control UDS transport requires Linux SO_PEERCRED support; use mTLS TCP on this platform")
}

func authenticatePrivateControlUDSConnection(net.Conn, privateControlPolicy) (net.Conn, string, error) {
	return nil, "", errors.New("private control UDS transport requires Linux SO_PEERCRED support")
}
