package obfs

import (
	"crypto/rand"
	"testing"
)

// --> ПОМОЩНИКИ <--

func testPSK(t *testing.T) []byte {
	t.Helper()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	return psk
}

func testKeyPair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := NewKeyPair(Config{
		PSK:   testPSK(t),
		Cover: CoverConfig{CoverMin: 0, CoverMax: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// --> WRAP / UNWRAP ROUNDTRIP <--

func TestWrapUnwrapC2S(t *testing.T) {
	kp := testKeyPair(t)
	payload := []byte("hello fantik roundtrip test")
	var sessionID uint64 = 0x1234567890ABCDEF
	var seq uint64 = 1

	blob, err := kp.WrapC2S(sessionID, seq, FlagData, payload, 0)
	if err != nil {
		t.Fatalf("WrapC2S: %v", err)
	}

	pkt, err := kp.UnwrapC2S(blob)
	if err != nil {
		t.Fatalf("UnwrapC2S: %v", err)
	}

	if pkt.SessionID != sessionID {
		t.Errorf("SessionID: got %x, want %x", pkt.SessionID, sessionID)
	}
	if pkt.Seq != seq {
		t.Errorf("Seq: got %d, want %d", pkt.Seq, seq)
	}
	if pkt.Flags != FlagData {
		t.Errorf("Flags: got %x, want %x", pkt.Flags, FlagData)
	}
	if string(pkt.Payload) != string(payload) {
		t.Errorf("Payload: got %q, want %q", pkt.Payload, payload)
	}
}

func TestWrapUnwrapS2C(t *testing.T) {
	kp := testKeyPair(t)
	payload := []byte("response from server")

	blob, err := kp.WrapS2C(42, 10, FlagData, payload, 0)
	if err != nil {
		t.Fatalf("WrapS2C: %v", err)
	}

	pkt, err := kp.UnwrapS2C(blob)
	if err != nil {
		t.Fatalf("UnwrapS2C: %v", err)
	}

	if string(pkt.Payload) != string(payload) {
		t.Errorf("Payload mismatch")
	}
}

// --> DIRECTION ISOLATION <--
// - пакет зашифрованный c2s не дешифруется s2c и наоборот -

func TestDirectionIsolation(t *testing.T) {
	kp := testKeyPair(t)

	// - c2s пакет не должен открываться как s2c -
	blob, err := kp.WrapC2S(1, 1, FlagData, []byte("test"), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = kp.UnwrapS2C(blob)
	if err != ErrAuthFailed {
		t.Errorf("c2s blob opened as s2c: expected ErrAuthFailed, got %v", err)
	}

	// - s2c пакет не должен открываться как c2s -
	blob2, err := kp.WrapS2C(1, 1, FlagData, []byte("test"), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = kp.UnwrapC2S(blob2)
	if err != ErrAuthFailed {
		t.Errorf("s2c blob opened as c2s: expected ErrAuthFailed, got %v", err)
	}
}

// --> EMPTY PAYLOAD (keepalive) <--

func TestWrapUnwrapEmptyPayload(t *testing.T) {
	kp := testKeyPair(t)

	blob, err := kp.WrapC2S(1, 1, FlagKeepalive, nil, 0)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	pkt, err := kp.UnwrapC2S(blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if len(pkt.Payload) != 0 {
		t.Errorf("Payload len: got %d, want 0", len(pkt.Payload))
	}
	if pkt.Flags != FlagKeepalive {
		t.Errorf("Flags: got %x, want %x", pkt.Flags, FlagKeepalive)
	}
}

// --> LARGE PAYLOAD <--

func TestWrapUnwrapLargePayload(t *testing.T) {
	kp := testKeyPair(t)
	payload := make([]byte, 1400)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	blob, err := kp.WrapC2S(42, 100, FlagData, payload, 0)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	pkt, err := kp.UnwrapC2S(blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if len(pkt.Payload) != len(payload) {
		t.Fatalf("Payload len: got %d, want %d", len(pkt.Payload), len(payload))
	}
	for i := range payload {
		if pkt.Payload[i] != payload[i] {
			t.Fatalf("Payload mismatch at byte %d", i)
		}
	}
}

// --> WRONG KEY <--

func TestUnwrapWrongKey(t *testing.T) {
	kp1 := testKeyPair(t)
	kp2 := testKeyPair(t)

	blob, err := kp1.WrapC2S(1, 1, FlagData, []byte("secret"), 0)
	if err != nil {
		t.Fatal(err)
	}

	_, err = kp2.UnwrapC2S(blob)
	if err != ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
}

// --> TAMPERED BLOB <--

func TestUnwrapTampered(t *testing.T) {
	kp := testKeyPair(t)

	blob, err := kp.WrapC2S(1, 1, FlagData, []byte("data"), 0)
	if err != nil {
		t.Fatal(err)
	}

	// - портим один байт в ciphertext -
	blob[len(blob)-5] ^= 0xFF

	_, err = kp.UnwrapC2S(blob)
	if err != ErrAuthFailed {
		t.Errorf("expected ErrAuthFailed, got %v", err)
	}
}

// --> TOO SHORT <--

func TestUnwrapTooShort(t *testing.T) {
	kp := testKeyPair(t)

	_, err := kp.UnwrapC2S(make([]byte, 10))
	if err != ErrBlobTooShort {
		t.Errorf("expected ErrBlobTooShort, got %v", err)
	}
}

// --> ALL FLAGS <--

func TestAllFlags(t *testing.T) {
	kp := testKeyPair(t)
	flags := []byte{FlagData, FlagKeepalive, FlagKeepaliveAck, FlagClose}

	for _, f := range flags {
		blob, err := kp.WrapC2S(1, 1, f, nil, 0)
		if err != nil {
			t.Fatalf("Wrap flag=%x: %v", f, err)
		}
		res, err := kp.UnwrapC2S(blob)
		if err != nil {
			t.Fatalf("Unwrap flag=%x: %v", f, err)
		}
		if res.Flags != f {
			t.Errorf("Flags: got %x, want %x", res.Flags, f)
		}
	}
}

// --> PAYLOAD TOO LARGE <--

func TestWrapPayloadTooLarge(t *testing.T) {
	kp := testKeyPair(t)
	huge := make([]byte, MaxPayloadSize+1)

	_, err := kp.WrapC2S(1, 1, FlagData, huge, 0)
	if err != ErrPayloadTooLarge {
		t.Errorf("expected ErrPayloadTooLarge, got %v", err)
	}
}

// --> SHORT PSK <--

func TestNewKeyPairShortPSK(t *testing.T) {
	_, err := NewKeyPair(Config{
		PSK:   []byte("short"),
		Cover: CoverConfig{},
	})
	if err != ErrInvalidPSK {
		t.Errorf("expected ErrInvalidPSK, got %v", err)
	}
}

// --> MTU CLAMPING <--

func TestWrapCoverClampedByMTU(t *testing.T) {
	kp, err := NewKeyPair(Config{
		PSK:   testPSK(t),
		Cover: CoverConfig{CoverMin: 100, CoverMax: 200},
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 100)
	// - maxPacket = 200, overhead(48) + payload(100) = 148, остаётся 52 на cover -
	blob, err := kp.WrapC2S(1, 1, FlagData, payload, 200)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if len(blob) > 200 {
		t.Errorf("blob size %d > maxPacket 200", len(blob))
	}

	pkt, err := kp.UnwrapC2S(blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if len(pkt.Payload) != 100 {
		t.Errorf("Payload len: got %d, want 100", len(pkt.Payload))
	}
}

func TestWrapPayloadExceedsMTU(t *testing.T) {
	kp := testKeyPair(t)

	// - payload 200 + overhead 48 = 248 > maxPacket 100 -
	_, err := kp.WrapC2S(1, 1, FlagData, make([]byte, 200), 100)
	if err != ErrPayloadExceedsMTU {
		t.Errorf("expected ErrPayloadExceedsMTU, got %v", err)
	}
}

// --> MAX OVERHEAD <--

func TestMaxOverhead(t *testing.T) {
	policy := CoverConfig{CoverMin: 0, CoverMax: 64}
	oh := MaxOverhead(policy)
	// - 12(nonce) + 20(inner header) + 64(cover) + 16(tag) = 112 -
	expected := 112
	if oh != expected {
		t.Errorf("MaxOverhead: got %d, want %d", oh, expected)
	}
}

// --> COVER BYTES VARY SIZE <--

func TestCoverBytesVarySize(t *testing.T) {
	kp, err := NewKeyPair(Config{
		PSK:   testPSK(t),
		Cover: CoverConfig{CoverMin: 10, CoverMax: 100},
	})
	if err != nil {
		t.Fatal(err)
	}

	sizes := make(map[int]bool)
	for i := 0; i < 100; i++ {
		blob, err := kp.WrapC2S(1, uint64(i+1), FlagData, []byte("x"), 0)
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(blob)] = true
	}

	if len(sizes) < 5 {
		t.Errorf("expected varied blob sizes, got only %d distinct sizes", len(sizes))
	}
}

// --> FRAME KEY <--

func TestFrameKeyDerived(t *testing.T) {
	kp := testKeyPair(t)
	fk := kp.FrameKey()
	if len(fk) != KeySize {
		t.Errorf("FrameKey length: got %d, want %d", len(fk), KeySize)
	}

	// - FrameKey возвращает копию -
	fk2 := kp.FrameKey()
	fk[0] ^= 0xFF
	if fk2[0] == fk[0] {
		t.Error("FrameKey should return a copy")
	}
}

func TestFrameKeyDeterministic(t *testing.T) {
	psk := testPSK(t)
	kp1, _ := NewKeyPair(Config{PSK: psk, Cover: CoverConfig{}})
	kp2, _ := NewKeyPair(Config{PSK: psk, Cover: CoverConfig{}})

	fk1 := kp1.FrameKey()
	fk2 := kp2.FrameKey()
	for i := range fk1 {
		if fk1[i] != fk2[i] {
			t.Fatal("FrameKey should be deterministic for same PSK")
		}
	}
}

// --> REPLAY WINDOW <--

func TestReplayBasic(t *testing.T) {
	rw := NewReplayWindow()

	if !rw.Check(1) {
		t.Error("seq=1 should be accepted")
	}
	rw.Accept(1)

	if rw.Check(1) {
		t.Error("seq=1 replay should be rejected")
	}

	if !rw.Check(2) {
		t.Error("seq=2 should be accepted")
	}
	rw.Accept(2)
}

func TestReplayOutOfOrder(t *testing.T) {
	rw := NewReplayWindow()
	rw.Accept(5)

	if !rw.Check(3) {
		t.Error("seq=3 should be accepted (within window)")
	}
	rw.Accept(3)

	if rw.Check(3) {
		t.Error("seq=3 replay should be rejected")
	}

	if !rw.Check(4) {
		t.Error("seq=4 should be accepted")
	}
	rw.Accept(4)
}

func TestReplayTooOld(t *testing.T) {
	rw := NewReplayWindow()
	rw.Accept(3000)

	if rw.Check(952) {
		t.Error("seq=952 should be rejected (too old)")
	}
	if rw.Check(1) {
		t.Error("seq=1 should be rejected (too old)")
	}
}

func TestReplaySeqZero(t *testing.T) {
	rw := NewReplayWindow()
	if rw.Check(0) {
		t.Error("seq=0 should always be rejected")
	}
}

func TestReplayLargeJump(t *testing.T) {
	rw := NewReplayWindow()
	rw.Accept(1)
	rw.Accept(2)

	if !rw.Check(1000) {
		t.Error("seq=1000 should be accepted")
	}
	rw.Accept(1000)

	if rw.Check(1) {
		t.Error("seq=1 should be too old after jump")
	}
}

func TestReplayCheckAndAccept(t *testing.T) {
	rw := NewReplayWindow()

	if !rw.CheckAndAccept(1) {
		t.Error("seq=1 should be accepted")
	}
	if rw.CheckAndAccept(1) {
		t.Error("seq=1 replay should be rejected")
	}
	if !rw.CheckAndAccept(2) {
		t.Error("seq=2 should be accepted")
	}
}

func TestReplayWindowBoundary(t *testing.T) {
	rw := NewReplayWindow()

	rw.Accept(2048)
	if !rw.Check(1) {
		t.Error("seq=1 should be within window (diff=2047)")
	}

	rw.Accept(2049)
	if rw.Check(1) {
		t.Error("seq=1 should be outside window (diff=2048)")
	}
}

func TestReplayReset(t *testing.T) {
	rw := NewReplayWindow()
	rw.CheckAndAccept(1)
	rw.CheckAndAccept(2)
	rw.Reset()

	if !rw.CheckAndAccept(1) {
		t.Error("seq=1 should be accepted after Reset")
	}
}

// --> БЕНЧ <--

func BenchmarkWrapC2S_148(b *testing.B) {
	benchWrap(b, 148)
}

func BenchmarkWrapC2S_1200(b *testing.B) {
	benchWrap(b, 1200)
}

func BenchmarkUnwrapC2S_148(b *testing.B) {
	benchUnwrap(b, 148)
}

func BenchmarkUnwrapC2S_1200(b *testing.B) {
	benchUnwrap(b, 1200)
}

func benchWrap(b *testing.B, payloadSize int) {
	psk := make([]byte, 32)
	rand.Read(psk)
	kp, _ := NewKeyPair(Config{
		PSK:   psk,
		Cover: CoverConfig{CoverMin: 4, CoverMax: 40},
	})
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = kp.WrapC2S(0x1234, uint64(i+1), FlagData, payload, 0)
	}
}

func benchUnwrap(b *testing.B, payloadSize int) {
	psk := make([]byte, 32)
	rand.Read(psk)
	kp, _ := NewKeyPair(Config{
		PSK:   psk,
		Cover: CoverConfig{CoverMin: 4, CoverMax: 40},
	})
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	blobs := make([][]byte, 1000)
	for i := range blobs {
		p, _ := kp.WrapC2S(0x1234, uint64(i+1), FlagData, payload, 0)
		blobs[i] = p
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = kp.UnwrapC2S(blobs[i%len(blobs)])
	}
}
