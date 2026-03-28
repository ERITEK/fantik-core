// Пакет 'frame' это TCP framing для Fantik.
//
// Проблема: TCP это поток байтов, а Fantik работает с пакетами (blob) значит нужен framing разделение потока на кадры. 
// Простой length prefix (2 байта длины в открытом виде) -> палится DPI. Поэтому длина маскируется через HMAC-SHA256 как PRF.
//
// Формат TCP кадра:
//	[EncLen 2B][Fantik blob NB]
// EncLen = uint16_be(blob_len) XOR HMAC-SHA256(frame_key, direction || uint64_be(counter))[0:2]
//
// frame_key - выводится из PSK через HKDF (см. obfs.KeyPair.FrameKey()).
// direction - 0x01 для c2s, 0x02 для s2c. Гарантирует разные маски для разных направлений даже при одинаковом counter.
// counter - монотонный uint64, начинается с 0, инкрементируется при каждом кадре. Отдельный для каждого направления и TCP соединения.
// Не передаётся -> синхронизация через порядок байтов в TCP потоке.
//
// На проводе TCP stream выглядит так:
//	[2 random bytes][12 random bytes][N random bytes][2 random bytes]...
// Для наблюдателя - сплошной поток случайных байтов.
//
// Типичное использование (клиент, отправка):
//
//	framer := frame.NewFramer(frameKey)
//	// ... для каждого blob:
//	frameBytes := framer.Encode(blob, frame.DirC2S)
//	conn.Write(frameBytes)
//
// Типичное использование (сервер, приём):
//
//	framer := frame.NewFramer(frameKey)
//	reader := bufio.NewReaderSize(conn, maxBlobSize*2)
//	// ... в цикле чтения:
//	blob, err := framer.ReadFrame(reader, frame.DirC2S, maxBlobSize)
//	if err != nil {
//	    conn.Close() // - ошибка framing -> disconnect -
//	    break
//	}
//
// !!! ВНИМАНИЕ ёпта: Framer НЕ потокобезопасен !!!
// Для двунаправленного TCP (чтение + запись из разных горутин) используйте два отдельных Framer или защищайте мьютексом. 
// Counter c2s и s2c внутри одного Framer независимы, но concurrent доступ к одному направлению сломает синхронизацию.
package frame

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// --> КОНСТАНТЫ <--

const (
	// EncLenSize - размер зашифрованной длины в TCP кадре (2 байта).
	EncLenSize = 2

	// MinBlobSize - минимальный размер blob внутри TCP кадра.
	// Совпадает с obfs.MinBlobSize (Nonce 12 + InnerHeader 20 + Tag 16 = 48).
	MinBlobSize = 48

	// DefaultMaxBlobSize - максимальный размер blob по умолчанию.
	// Защита от OOM при получении мусора. 'Конфигурируемый'.
	DefaultMaxBlobSize = 4096
)

// --> НАПРАВЛЕНИЕ <--

// Direction - байт направления для HMAC input.
// Гарантирует что маски c2s и s2c никогда не совпадут при одинаковом counter.
type Direction byte

const (
	// DirC2S - направление client -> server (0x01).
	DirC2S Direction = 0x01

	// DirS2C - направление server -> client (0x02).
	DirS2C Direction = 0x02
)

// --> ОШИБКИ <--

var (
	// ErrFrameDesync - длина из EncLen невалидна (< MinBlobSize или > maxBlobSize).
	// TCP соединение десинхронизировано -> нужен disconnect.
	ErrFrameDesync = errors.New("frame: desync (невалидная длина blob, нужен disconnect)")

	// ErrInvalidFrameKey - frame_key пустой или неверной длины.
	ErrInvalidFrameKey = errors.New("frame: невалидный frame_key (нужен 32 байта)")
)

// --> FRAMER <--

// Framer - кодирует/декодирует TCP кадры с HMAC-masked длиной.
//
// Содержит два независимых counter: для c2s и s2c.
// При создании нового TCP соединения -> создавайте новый Framer.
type Framer struct {
	key      []byte // - frame_key (32 байта) -
	counters [2]uint64 // - [0] = c2s counter, [1] = s2c counter -
}

// NewFramer - создаёт Framer для одного TCP соединения.
// frameKey - 32 байта, получается из obfs.KeyPair.FrameKey().
func NewFramer(frameKey []byte) (*Framer, error) {
	if len(frameKey) != 32 {
		return nil, ErrInvalidFrameKey
	}
	key := make([]byte, 32)
	copy(key, frameKey)
	return &Framer{key: key}, nil
}

// Encode - кодирует blob в TCP кадр = [EncLen 2B][blob].
//
// dir - направление (DirC2S при отправке клиентом, DirS2C при отправке сервером).
// Инкрементирует(кто придумал это слово, зачем...) counter для указанного направления.
// Возвращает готовые байты для записи в TCP соединение.
func (f *Framer) Encode(blob []byte, dir Direction) []byte {
	blobLen := uint16(len(blob))

	// - вычисляем маску: HMAC-SHA256(frame_key, direction || counter)[0:2] -
	mask := f.computeMask(dir)

	// - EncLen = длина XOR маска -
	var encLen [EncLenSize]byte
	binary.BigEndian.PutUint16(encLen[:], blobLen)
	encLen[0] ^= mask[0]
	encLen[1] ^= mask[1]

	// - инкрементируем counter -
	f.incrementCounter(dir)

	// - собираем кадр: EncLen || blob -
	out := make([]byte, EncLenSize+len(blob))
	copy(out[:EncLenSize], encLen[:])
	copy(out[EncLenSize:], blob)

	return out
}

// ReadFrame - читает один TCP кадр из потока и возвращает blob.
//
// dir - направление с точки зрения отправителя.
//	Сервер читает от клиента -> DirC2S.
//	Клиент читает от сервера -> DirS2C.
//
// maxBlobSize - максимальный допустимый размер blob (защита от OOM).
// Используйте DefaultMaxBlobSize (4096) если нет особых требований.
//
// При любой ошибке (десинхронизация, EOF, мусор) -> закрывайте TCP соединение.
// Попытки ресинхронизации в зашифрованном потоке ненадёжны.
func (f *Framer) ReadFrame(r io.Reader, dir Direction, maxBlobSize int) ([]byte, error) {
	// - читаем 2 байта EncLen -
	var encLen [EncLenSize]byte
	if _, err := io.ReadFull(r, encLen[:]); err != nil {
		return nil, fmt.Errorf("frame: чтение EncLen: %w", err)
	}

	// - вычисляем маску и дешифруем длину -
	mask := f.computeMask(dir)
	encLen[0] ^= mask[0]
	encLen[1] ^= mask[1]
	blobLen := int(binary.BigEndian.Uint16(encLen[:]))

	// - инкрементируем counter -
	f.incrementCounter(dir)

	// - проверяем что длина в допустимых границах -
	if blobLen < MinBlobSize || blobLen > maxBlobSize {
		return nil, ErrFrameDesync
	}

	// - читаем blob целиком -
	blob := make([]byte, blobLen)
	if _, err := io.ReadFull(r, blob); err != nil {
		return nil, fmt.Errorf("frame: чтение blob (%d байт): %w", blobLen, err)
	}

	return blob, nil
}

// --> ВНУТРЕННИЕ МЕТОДЫ <--

// computeMask - вычисляет 2-байтовую маску для текущего counter.
//
// mask = HMAC-SHA256(frame_key, direction_byte || uint64_be(counter))[0:2]
func (f *Framer) computeMask(dir Direction) [2]byte {
	// - собираем input: direction(1) || counter(8) = 9 байт -
	var input [9]byte
	input[0] = byte(dir)
	idx := f.dirIndex(dir)
	binary.BigEndian.PutUint64(input[1:], f.counters[idx])

	// - HMAC-SHA256 -
	mac := hmac.New(sha256.New, f.key)
	mac.Write(input[:])
	sum := mac.Sum(nil) // 32 байта

	// - берём первые 2 байта -
	return [2]byte{sum[0], sum[1]}
}

// incrementCounter - инкрементирует counter для указанного направления.
func (f *Framer) incrementCounter(dir Direction) {
	idx := f.dirIndex(dir)
	f.counters[idx]++
}

// dirIndex - индекс в массиве counters по направлению.
func (f *Framer) dirIndex(dir Direction) int {
	if dir == DirS2C {
		return 1
	}
	return 0 // DirC2S
}
