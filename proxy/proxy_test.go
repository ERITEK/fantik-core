package proxy

import (
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ERITEK/fantik-core/obfs"
)

// --> HELPERS <--

func testKeys(t *testing.T) *obfs.KeyPair {
	t.Helper()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	kp, err := obfs.NewKeyPair(obfs.Config{
		PSK:   psk,
		Cover: obfs.CoverConfig{CoverMin: 0, CoverMax: 16},
	})
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func freePort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port
}

// - echoUpstream - эхо-сервер имитирующий upstream (отвечает тем же что получил) -
func echoUpstream(t *testing.T, addr string) (*net.UDPConn, func()) {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", a)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			conn.WriteToUDP(buf[:n], remoteAddr)
		}
	}()

	return conn, func() {
		close(done)
		conn.Close()
	}
}

// --> INTEGRATION (ПОЛНАЯ ЦЕПОЧКА) <--
// - upstream app -> client -> server -> echo upstream -> server -> client -> upstream app -

func TestIntegrationRoundtrip(t *testing.T) {
	keys := testKeys(t)

	upPort := freePort(t)
	serverPort := freePort(t)
	clientPort := freePort(t)

	upAddr := fmt.Sprintf("127.0.0.1:%d", upPort)
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	clientAddr := fmt.Sprintf("127.0.0.1:%d", clientPort)

	_, upStop := echoUpstream(t, upAddr)
	defer upStop()

	srv := NewUDPServer(UDPServerOpts{
		ListenAddr:   serverAddr,
		UpstreamAddr: upAddr,
		Keys:         keys,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	defer srv.Stop()

	client := NewUDPClient(UDPClientOpts{
		ListenAddr:        clientAddr,
		ServerAddr:        serverAddr,
		Keys:              keys,
		KeepaliveInterval: 60 * time.Second,
	})
	if err := client.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	defer client.Stop()

	// - отправляем данные "от upstream приложения" на clientAddr -
	upApp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: clientPort})
	if err != nil {
		t.Fatal(err)
	}
	defer upApp.Close()

	testPayload := []byte("hello fantik roundtrip test")
	if _, err := upApp.Write(testPayload); err != nil {
		t.Fatal(err)
	}

	upApp.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 65535)
	n, err := upApp.Read(resp)
	if err != nil {
		t.Fatalf("no response from echo: %v", err)
	}

	if string(resp[:n]) != string(testPayload) {
		t.Errorf("response mismatch: got %q, want %q", resp[:n], testPayload)
	}
}

// --> BURST TEST <--

func TestIntegrationBurst(t *testing.T) {
	keys := testKeys(t)

	upPort := freePort(t)
	serverPort := freePort(t)
	clientPort := freePort(t)

	_, upStop := echoUpstream(t, fmt.Sprintf("127.0.0.1:%d", upPort))
	defer upStop()

	srv := NewUDPServer(UDPServerOpts{
		ListenAddr:   fmt.Sprintf("127.0.0.1:%d", serverPort),
		UpstreamAddr: fmt.Sprintf("127.0.0.1:%d", upPort),
		Keys:         keys,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	client := NewUDPClient(UDPClientOpts{
		ListenAddr:        fmt.Sprintf("127.0.0.1:%d", clientPort),
		ServerAddr:        fmt.Sprintf("127.0.0.1:%d", serverPort),
		Keys:              keys,
		KeepaliveInterval: 60 * time.Second,
	})
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Stop()

	upApp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: clientPort})
	if err != nil {
		t.Fatal(err)
	}
	defer upApp.Close()

	const count = 50
	for i := 0; i < count; i++ {
		msg := fmt.Sprintf("packet-%03d", i)
		upApp.Write([]byte(msg))
	}

	received := 0
	upApp.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	for received < count {
		_, err := upApp.Read(buf)
		if err != nil {
			break
		}
		received++
	}

	// - допускаем потерю до 10% (UDP, localhost) -
	if received < count*90/100 {
		t.Errorf("burst: received %d/%d (< 90%%)", received, count)
	}
	t.Logf("burst: received %d/%d", received, count)
}

// --> МУСОРНЫЕ ПАКЕТЫ <--

func TestServerHandlesGarbage(t *testing.T) {
	keys := testKeys(t)

	serverPort := freePort(t)
	upPort := freePort(t)

	_, upStop := echoUpstream(t, fmt.Sprintf("127.0.0.1:%d", upPort))
	defer upStop()

	srv := NewUDPServer(UDPServerOpts{
		ListenAddr:   fmt.Sprintf("127.0.0.1:%d", serverPort),
		UpstreamAddr: fmt.Sprintf("127.0.0.1:%d", upPort),
		Keys:         keys,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	garbage := make([]byte, 200)
	for i := 0; i < 1000; i++ {
		rand.Read(garbage)
		conn.Write(garbage)
	}

	time.Sleep(500 * time.Millisecond)

	if srv.SessionCount() != 0 {
		t.Errorf("sessions after garbage: %d, want 0", srv.SessionCount())
	}
}

// --> CLIENT STATE <--

func TestClientStateString(t *testing.T) {
	tests := map[ClientState]string{
		ClientIdle:         "IDLE",
		ClientStarting:     "STARTING",
		ClientEstablished:  "ESTABLISHED",
		ClientDegraded:     "DEGRADED",
		ClientReconnecting: "RECONNECTING",
		ClientClosed:       "CLOSED",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("ClientState(%d).String(): got %q, want %q", s, got, want)
		}
	}
}
