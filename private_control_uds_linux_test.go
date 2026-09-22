//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPrivateControlUDSAuthenticatesPeerUID(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("test requires a non-root Linux user and group")
	}
	relay := newTestUDPConn(t)
	link, err := newPrivateControlLink(newServer(relay, false, false, false, 0, false, 1), privateControlPolicy{byUID: map[uint32]string{uint32(os.Geteuid()): "management-main"}}, "relay-test", filepath.Join(t.TempDir(), "private-control-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(t.TempDir(), "relay.sock")
	listener, err := startPrivateControlUDSListener(privateControlConfig{udsSocketPath: socketPath, udsSocketGroup: strconv.Itoa(os.Getegid())})
	if err != nil {
		t.Fatalf("start UDS listener: %v", err)
	}
	defer listener.Close()
	link.authenticate = authenticatePrivateControlUDSConnection
	go link.acceptLoop(listener)

	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial UDS: %v", err)
	}
	defer connection.Close()
	wantEvents, wantAuditInputs, wantDiagnostics := false, false, false
	if err := writePrivateControlFrame(connection, privateControlHello{
		SchemaVersion: privateControlSchemaVersion, Type: "hello", MessageID: "MDEyMzQ1Njc4OTo7PD0-Pw", ManagementServiceID: "management-main",
		WantLifecycleEvents: &wantEvents, WantAuditInputs: &wantAuditInputs, WantDiagnostics: &wantDiagnostics,
	}); err != nil {
		t.Fatalf("write UDS hello: %v", err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	rawAck, err := readPrivateControlFrame(connection)
	if err != nil {
		t.Fatalf("read UDS hello_ack: %v", err)
	}
	var ack privateControlHelloAck
	if err := decodePrivateControlJSON(rawAck, &ack); err != nil {
		t.Fatalf("decode UDS hello_ack: %v", err)
	}
	if ack.Type != "hello_ack" || ack.InReplyTo != "MDEyMzQ1Njc4OTo7PD0-Pw" || ack.RelayID != "relay-test" {
		t.Fatalf("unexpected UDS hello_ack: %+v", ack)
	}
}
