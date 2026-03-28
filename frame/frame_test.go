package frame

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// --> ПоМОЩНИКИ <--

func testFrameKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func testFramer(t *testing.T) *Framer {
	t.Helper()
	f, err := NewFramer(testFrameKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// - makeBlob: создаёт фейковый blob заданной длины -
func makeBlob(t *testing.T, size int) []byte {
	t.Helper()
	blob := make([]byte, size)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	return blob
}

// --> ENCODE / READFRAME ROUNDTRIP <--

func TestEncodeReadFrameRoundtrip(t *testing.T) {
	key := testFrameKey(t)
	encoder, _ := NewFramer(key)
	decoder, _ := NewFramer(key)

	blob := makeBlob(t, 100)
	frame := encoder.Encode(blob, DirC2S)

	// - frame = EncLen(2) + blob(100) = 102 байта -
	if len(frame) != EncLenSize+len(blob) {
		t.Fatalf("frame size: got %d, want %d", len(frame), EncLenSize+len(blob))
	}

	reader := bytes.NewReader(frame)
	got, err := decoder.ReadFrame(reader, DirC2S, DefaultMaxBlobSize)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if !bytes.Equal(got, blob) {
		t.Error("blob mismatch after roundtrip")
	}
}

// --> COUNTER SYNC: 100 КАДРОВ <--

func TestCounterSync100Frames(t *testing.T) {
	key := testFrameKey(t)
	encoder, _ := NewFramer(key)
	decoder, _ := NewFramer(key)

	var buf bytes.Buffer

	// - кодируем 100 кадров -
	for i := 0; i < 100; i++ {
		blob := makeBlob(t, 60+i) // - разные размеры -
		frame := encoder.Encode(blob, DirC2S)
		buf.Write(frame)
	}

	// - декодируем 100 кадров, counter должен синхронизироваться -
	reader := bytes.NewReader(buf.Bytes())
	for i := 0; i < 100; i++ {
		got, err := decoder.ReadFrame(reader, DirC2S, DefaultMaxBlobSize)
		if err != nil {
			t.Fatalf("ReadFrame #%d: %v", i, err)
		}
		expectedLen := 60 + i
		if len(got) != expectedLen {
			t.Fatalf("frame #%d: blob len got %d, want %d", i, len(got), expectedLen)
		}
	}
}

// --> DIRECTION ISOLATION <--
// - кадр закодированный как c2s не декодируется как s2c -

func TestDirectionIsolation(t *testing.T) {
	key := testFrameKey(t)
	encoder, _ := NewFramer(key)
	decoder, _ := NewFramer(key)

	blob := makeBlob(t, 100)
	frame := encoder.Encode(blob, DirC2S)

	reader := bytes.NewReader(frame)
	// - пробуем декодировать с другим направлением -
	_, err := decoder.ReadFrame(reader, DirS2C, DefaultMaxBlobSize)
	// - должна быть ошибка: либо desync, либо некорректная длина -
	if err == nil {
		t.Error("expected error when decoding c2s frame as s2c")
	}
}

// --> BIDIRECTIONAL: c2s + s2c <--

func TestBidirectional(t *testing.T) {
	key := testFrameKey(t)
	clientFramer, _ := NewFramer(key)
	serverFramer, _ := NewFramer(key)

	blobC2S := makeBlob(t, 80)
	blobS2C := makeBlob(t, 120)

	// - клиент отправляет c2s -
	frameC2S := clientFramer.Encode(blobC2S, DirC2S)
	// - сервер отправляет s2c -
	frameS2C := serverFramer.Encode(blobS2C, DirS2C)

	// - сервер читает c2s -
	gotC2S, err := serverFramer.ReadFrame(bytes.NewReader(frameC2S), DirC2S, DefaultMaxBlobSize)
	if err != nil {
		t.Fatalf("server ReadFrame c2s: %v", err)
	}
	if !bytes.Equal(gotC2S, blobC2S) {
		t.Error("c2s blob mismatch")
	}

	// - клиент читает s2c -
	gotS2C, err := clientFramer.ReadFrame(bytes.NewReader(frameS2C), DirS2C, DefaultMaxBlobSize)
	if err != nil {
		t.Fatalf("client ReadFrame s2c: %v", err)
	}
	if !bytes.Equal(gotS2C, blobS2C) {
		t.Error("s2c blob mismatch")
	}
}

// --> INVALID FRAME KEY <--

func TestNewFramerInvalidKey(t *testing.T) {
	_, err := NewFramer([]byte("short"))
	if err != ErrInvalidFrameKey {
		t.Errorf("expected ErrInvalidFrameKey, got %v", err)
	}

	_, err = NewFramer(nil)
	if err != ErrInvalidFrameKey {
		t.Errorf("expected ErrInvalidFrameKey for nil, got %v", err)
	}
}

// --> DESYNC: МУСОР ВМЕСТО КАДРА <--

func TestDesyncGarbage(t *testing.T) {
	decoder := testFramer(t)
	garbage := makeBlob(t, 100)

	reader := bytes.NewReader(garbage)
	_, err := decoder.ReadFrame(reader, DirC2S, DefaultMaxBlobSize)
	// - маска не совпадёт, длина будет мусорной -> desync или read error -
	if err == nil {
		t.Error("expected error on garbage input")
	}
}

// --> EOF <--

func TestReadFrameEOF(t *testing.T) {
	decoder := testFramer(t)

	// - пустой reader -
	_, err := decoder.ReadFrame(bytes.NewReader(nil), DirC2S, DefaultMaxBlobSize)
	if err == nil {
		t.Error("expected error on empty reader")
	}

	// - только 1 байт (неполный EncLen) -
	_, err = decoder.ReadFrame(bytes.NewReader([]byte{0x42}), DirC2S, DefaultMaxBlobSize)
	if err == nil {
		t.Error("expected error on partial EncLen")
	}
}

// --> PARTIAL READ (TCP recv по 1 байту) <--

func TestPartialReads(t *testing.T) {
	key := testFrameKey(t)
	encoder, _ := NewFramer(key)
	decoder, _ := NewFramer(key)

	blob := makeBlob(t, 80)
	frame := encoder.Encode(blob, DirC2S)

	// - oneByteReader отдаёт по 1 байту за раз, имитируя медленный TCP -
	reader := &oneByteReader{data: frame}
	got, err := decoder.ReadFrame(reader, DirC2S, DefaultMaxBlobSize)
	if err != nil {
		t.Fatalf("ReadFrame with slow reader: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Error("blob mismatch with slow reader")
	}
}

// - oneByteReader - io.Reader который отдаёт по 1 байту -
type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

// --> ENCLEN ВЫГЛЯДИТ КАК RANDOM <--

func TestEncLenLooksRandom(t *testing.T) {
	key := testFrameKey(t)
	encoder, _ := NewFramer(key)

	// - кодируем один и тот же blob 100 раз (counter инкрементируется) -
	blob := makeBlob(t, 100)
	encLens := make(map[[2]byte]bool)

	for i := 0; i < 100; i++ {
		frame := encoder.Encode(blob, DirC2S)
		var el [2]byte
		copy(el[:], frame[:2])
		encLens[el] = true
	}

	// - при одинаковом blob_len, EncLen должен отличаться (разные counter) -
	if len(encLens) < 50 {
		t.Errorf("EncLen not random enough: only %d unique values from 100 frames", len(encLens))
	}
}

// --> MAX BLOB SIZE PROTECTION <--

func TestMaxBlobSizeProtection(t *testing.T) {
	key := testFrameKey(t)
	encoder, _ := NewFramer(key)
	decoder, _ := NewFramer(key)

	// - кодируем blob в 2000 байт -
	bigBlob := makeBlob(t, 2000)
	frame := encoder.Encode(bigBlob, DirC2S)

	// - пробуем декодировать с maxBlobSize=1000 -> desync -
	_, err := decoder.ReadFrame(bytes.NewReader(frame), DirC2S, 1000)
	if err != ErrFrameDesync {
		t.Errorf("expected ErrFrameDesync, got %v", err)
	}
}

// --> БЕНЧ <--

func BenchmarkEncode(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	f, _ := NewFramer(key)
	blob := make([]byte, 200)
	rand.Read(blob)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = f.Encode(blob, DirC2S)
	}
}

func BenchmarkReadFrame(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	encoder, _ := NewFramer(key)
	blob := make([]byte, 200)
	rand.Read(blob)

	// - заготавливаем кадры -
	frames := make([][]byte, 1000)
	for i := range frames {
		frames[i] = encoder.Encode(blob, DirC2S)
	}
	allBytes := bytes.Join(frames, nil)

	decoder, _ := NewFramer(key)
	b.ResetTimer()
	b.ReportAllocs()

	reader := bytes.NewReader(allBytes)
	for i := 0; i < b.N; i++ {
		if i%1000 == 0 {
			reader.Reset(allBytes)
			decoder, _ = NewFramer(key)
		}
		_, _ = decoder.ReadFrame(reader, DirC2S, DefaultMaxBlobSize)
	}
}
