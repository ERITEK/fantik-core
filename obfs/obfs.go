// Пакет obfs - ядро обфускации Fantik.
//
// Берёт любые UDP пакеты и заворачивает в AEAD шифрованный blob.
// На выходе чистый шум, никаких паттернов.
// Крипта: ChaCha20-Poly1305 (RFC 8439), ключи из PSK через HKDF-SHA256.
// Три ключа: c2s (клиент->сервер), s2c (сервер->клиент), frame (TCP framing).
//
// Blob на проводе:
//
//	[Nonce 12B][AEAD ciphertext + Tag 16B]
//
// Inner packet (plaintext внутри AEAD):
//
//	[Version 1B][SessionID 8B][Seq 8B][Flags 1B][PayloadLen 2B][Payload 0..N][Cover 0..M]
//
// Как юзать:
//
//	// 1. Создаём ключи из PSK (один раз при старте)
//	kp, err := obfs.NewKeyPair(obfs.Config{
//	    PSK:   myPSK,                                       // >= 16 байт
//	    Cover: obfs.CoverConfig{CoverMin: 4, CoverMax: 64}, // рандомный padding
//	})
//
//	// 2. Клиент шифрует пакет
//	blob, err := kp.WrapC2S(sessionID, seq, obfs.FlagData, payload, maxPacket)
//
//	// 3. Сервер расшифровывает
//	pkt, err := kp.UnwrapC2S(blob)
//	// pkt.SessionID, pkt.Seq, pkt.Flags, pkt.Payload - всё на месте
//
//	// 4. Сервер шифрует ответ
//	blob, err = kp.WrapS2C(sessionID, seq, obfs.FlagData, response, maxPacket)
//
//	// 5. Клиент расшифровывает ответ
//	pkt, err = kp.UnwrapS2C(blob)
package obfs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// --> КОНСТАНТЫ ПРОТОКОЛА <--
// - размеры полей wire format и криптографические параметры -

const (
	// ProtoVersion - версия wire format. Проверяется при распаковке.
	// Если версия не совпадает - пакет отбрасывается.
	ProtoVersion byte = 0x01

	// NonceSize - размер nonce для ChaCha20-Poly1305 (12 байт).
	// Каждый пакет получает случайный nonce из crypto/rand.
	NonceSize = chacha20poly1305.NonceSize // 12

	// TagSize - размер authentication tag AEAD (16 байт).
	TagSize = chacha20poly1305.Overhead // 16

	// InnerHeaderSize - фиксированная часть inner packet:
	// Version(1) + SessionID(8) + Seq(8) + Flags(1) + PayloadLen(2) = 20 байт.
	InnerHeaderSize = 1 + 8 + 8 + 1 + 2 // 20

	// MinBlobSize - минимальный размер blob на проводе:
	// Nonce(12) + InnerHeader(20) + Tag(16) = 48 байт.
	// Пакеты короче - точно мусор, можно дропать до расшифровки.
	MinBlobSize = NonceSize + InnerHeaderSize + TagSize // 48

	// MaxPayloadSize - максимальный размер payload (upstream пакет).
	// Ограничен 2 байтами PayloadLen в inner header.
	MaxPayloadSize = 65535

	// KeySize - размер ключа ChaCha20-Poly1305 (32 байта).
	KeySize = chacha20poly1305.KeySize // 32

	// HKDFSalt - соль для HKDF-Extract. Фиксированная, domain separation.
	HKDFSalt = "fantik-core"

	// HKDFInfoC2S - info label для вывода ключа направления client -> server.
	HKDFInfoC2S = "fantik-core-c2s"

	// HKDFInfoS2C - info label для вывода ключа направления server -> client.
	HKDFInfoS2C = "fantik-core-s2c"

	// HKDFInfoFrame - info label для вывода ключа TCP framing.
	// Используется пакетом frame/ для маскировки длин в TCP потоке.
	HKDFInfoFrame = "fantik-core-frame"
)

// --> ФЛАГИ ПАКЕТОВ <--
// - битовая маска в поле Flags inner header, определяет тип пакета -

const (
	// FlagData - обычный пакет с payload (upstream данные).
	FlagData byte = 0x01

	// FlagKeepalive - запрос keepalive от клиента к серверу.
	// Payload пустой. Сервер должен ответить FlagKeepaliveAck.
	FlagKeepalive byte = 0x02

	// FlagKeepaliveAck - ответ сервера на keepalive.
	FlagKeepaliveAck byte = 0x04

	// FlagClose - graceful close сессии.
	// После отправки Close клиент генерирует новый SessionID.
	FlagClose byte = 0x08
)

// --> ОШИБКИ <--
// - все ошибки пакета obfs, проверяемые через errors.Is -

var (
	ErrBlobTooShort    = errors.New("obfs: blob короче минимума (48 байт)")
	ErrBlobTooLong     = errors.New("obfs: blob превышает максимальный размер")
	ErrAuthFailed      = errors.New("obfs: AEAD аутентификация не прошла (неверный ключ или повреждение)")
	ErrBadVersion      = errors.New("obfs: неподдерживаемая версия протокола")
	ErrMalformedInner  = errors.New("obfs: битый inner packet (PayloadLen выходит за границы)")
	ErrPayloadTooLarge = errors.New("obfs: payload превышает 65535 байт")
	ErrPayloadExceedsMTU = errors.New("obfs: payload не влезает в указанный maxPacket даже без cover")
	ErrInvalidPSK      = errors.New("obfs: PSK должен быть >= 16 байт")
)

// --> ТИПЫ <--

// CoverConfig - диапазон случайных cover bytes, добавляемых в конец inner packet.
// Cover рандомизирует размер blob, затрудняя анализ трафика по размерам пакетов.
//
// Рекомендуемые профили:
//
//	Stable:     CoverMin=0,  CoverMax=16   - минимальный overhead
//	Balanced:   CoverMin=4,  CoverMax=64   - оптимальный баланс (рекомендуется)
//	Aggressive: CoverMin=16, CoverMax=128  - максимальная рандомизация размеров
type CoverConfig struct {
	CoverMin int // - минимальная длина cover (байт) -
	CoverMax int // - максимальная длина cover (байт) -
}

// Config - параметры для создания KeyPair.
type Config struct {
	PSK   []byte      // - общий секретный ключ, >= 16 байт. Обычно 32 или 64 байта -
	Cover CoverConfig // - диапазон cover bytes для рандомизации размера пакетов -
}

// KeyPair - пара ключей (c2s + s2c) + ключ TCP framing, готовая к использованию.
// Создаётся один раз из PSK, потокобезопасна для чтения (Wrap/Unwrap).
// Один и тот же KeyPair используется и на клиенте, и на сервере.
type KeyPair struct {
	c2s      *envelope
	s2c      *envelope
	frameKey []byte      // - ключ для TCP framing (32 байта), см. пакет frame/ -
	cover    CoverConfig
}

// - envelope - один направленный шифратор (c2s или s2c) -
type envelope struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
}

// Packet - результат распаковки blob (Unwrap).
// Содержит все поля inner header и извлечённый payload.
// Cover bytes отбрасываются автоматически.
type Packet struct {
	SessionID uint64 // - идентификатор сессии (8 байт, генерируется клиентом) -
	Seq       uint64 // - порядковый номер пакета (нумерация с 1, per-direction) -
	Flags     byte   // - тип пакета: FlagData, FlagKeepalive, FlagKeepaliveAck, FlagClose -
	Payload   []byte // - upstream данные (пустой для keepalive/close) -
}

// --> ИНИЦИАЛИЗАЦИЯ <--
// - вывод трёх ключей из PSK через HKDF-SHA256: c2s, s2c, frame -

// NewKeyPair - создаёт ключи из PSK.
// PSK >= 16 байт, ! РЕКОМЕНДУЕТСЯ ! 32 или 64.
// Выводит три ключа: c2s, s2c, frame_key (для TCP framing).
// Возвращённый KeyPair потокобезопасен для Wrap/Unwrap.
func NewKeyPair(cfg Config) (*KeyPair, error) {
	if len(cfg.PSK) < 16 {
		return nil, ErrInvalidPSK
	}

	// - HKDF-Extract: PSK + salt -> PRK -
	prk := hkdf.Extract(sha256.New, cfg.PSK, []byte(HKDFSalt))

	// - HKDF-Expand: PRK -> client_key, server_key, frame_key -
	c2sKey, err := deriveKey(prk, HKDFInfoC2S)
	if err != nil {
		return nil, fmt.Errorf("obfs: вывод ключа c2s: %w", err)
	}
	s2cKey, err := deriveKey(prk, HKDFInfoS2C)
	if err != nil {
		return nil, fmt.Errorf("obfs: вывод ключа s2c: %w", err)
	}
	frameKey, err := deriveKey(prk, HKDFInfoFrame)
	if err != nil {
		return nil, fmt.Errorf("obfs: вывод ключа frame: %w", err)
	}

	c2sAEAD, err := chacha20poly1305.New(c2sKey)
	if err != nil {
		return nil, fmt.Errorf("obfs: создание AEAD c2s: %w", err)
	}
	s2cAEAD, err := chacha20poly1305.New(s2cKey)
	if err != nil {
		return nil, fmt.Errorf("obfs: создание AEAD s2c: %w", err)
	}

	return &KeyPair{
		c2s:      &envelope{aead: c2sAEAD},
		s2c:      &envelope{aead: s2cAEAD},
		frameKey: frameKey,
		cover:    cfg.Cover,
	}, nil
}

// FrameKey - возвращает ключ для TCP framing (32 байта).
// Нужен пакету frame/ для маскировки длин. Возвращает копию.
func (kp *KeyPair) FrameKey() []byte {
	out := make([]byte, len(kp.frameKey))
	copy(out, kp.frameKey)
	return out
}

// deriveKey - HKDF-Expand из PRK по info label, 32 байта на выходе.
func deriveKey(prk []byte, info string) ([]byte, error) {
	r := hkdf.Expand(sha256.New, prk, []byte(info))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// --> WRAP (CLIENT -> SERVER) <--
// - шифрование payload в направлении c2s -

// WrapC2S - шифрует payload в blob, направление client -> server.
//
// sessionID - id сессии (8 байт, crypto/rand, генерит клиент).
// seq - порядковый номер (с 1, инкрементируется).
// flags - тип пакета (FlagData, FlagKeepalive, FlagClose).
// payload - данные upstream (nil для keepalive/close).
// maxPacket - макс размер blob (0 = без лимита).
//
//	Для UDP ставь network_mtu - 28 (IP/UDP overhead), предельный диапазон 1280 - 1472.
//	Для TCP ставь 0.
//	Если payload не лезет даже без cover - вернёт ErrPayloadExceedsMTU.
func (kp *KeyPair) WrapC2S(sessionID, seq uint64, flags byte, payload []byte, maxPacket int) ([]byte, error) {
	return wrap(kp.c2s, kp.cover, sessionID, seq, flags, payload, maxPacket)
}

// --> WRAP (SERVER -> CLIENT) <--
// - шифрование payload в направлении s2c -

// WrapS2C - шифрует payload в blob, направление server -> client.
// Параметры те же что у WrapC2S, ключ другой (s2c).
func (kp *KeyPair) WrapS2C(sessionID, seq uint64, flags byte, payload []byte, maxPacket int) ([]byte, error) {
	return wrap(kp.s2c, kp.cover, sessionID, seq, flags, payload, maxPacket)
}

// --> UNWRAP (CLIENT -> SERVER) <--
// - расшифровка blob в направлении c2s (вызывается на сервере) -

// UnwrapC2S - расшифровывает blob, направление client -> server.
// Дёргается на сервере для входящих пакетов от клиента.
// Возвращает Packet с SessionID, Seq, Flags, Payload. Cover отбрасывается.
//
// Ошибки: ErrBlobTooShort, ErrAuthFailed, ErrBadVersion, ErrMalformedInner.
func (kp *KeyPair) UnwrapC2S(blob []byte) (*Packet, error) {
	return unwrap(kp.c2s, blob)
}

// --> UNWRAP (SERVER -> CLIENT) <--
// - расшифровка blob в направлении s2c (вызывается на клиенте) -

// UnwrapS2C - расшифровывает blob, направление server -> client.
// Дёргается на клиенте для входящих пакетов от сервера.
func (kp *KeyPair) UnwrapS2C(blob []byte) (*Packet, error) {
	return unwrap(kp.s2c, blob)
}

// --> WRAP (общая логика) <--

func wrap(env *envelope, cover CoverConfig, sessionID, seq uint64, flags byte, payload []byte, maxPacket int) ([]byte, error) {
	if len(payload) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	// - выбираем случайную длину cover, потом clamp по MTU -
	coverLen := randRange(cover.CoverMin, cover.CoverMax)
	overhead := NonceSize + InnerHeaderSize + TagSize // 48 байт
	totalNeeded := overhead + len(payload) + coverLen

	if maxPacket > 0 && totalNeeded > maxPacket {
		// - урезаем cover чтобы влезть в maxPacket -
		coverLen = maxPacket - overhead - len(payload)
		if coverLen < 0 {
			coverLen = 0
		}
		// - если даже без cover не влезает - payload слишком большой -
		if overhead+len(payload) > maxPacket {
			return nil, ErrPayloadExceedsMTU
		}
	}

	// - собираем inner plaintext -
	innerSize := InnerHeaderSize + len(payload) + coverLen
	inner := make([]byte, innerSize)

	inner[0] = ProtoVersion
	binary.BigEndian.PutUint64(inner[1:9], sessionID)
	binary.BigEndian.PutUint64(inner[9:17], seq)
	inner[17] = flags
	binary.BigEndian.PutUint16(inner[18:20], uint16(len(payload)))

	copy(inner[InnerHeaderSize:], payload)

	// - заполняем cover случайными байтами (crypto/rand) -
	if coverLen > 0 {
		coverStart := InnerHeaderSize + len(payload)
		if _, err := rand.Read(inner[coverStart : coverStart+coverLen]); err != nil {
			return nil, fmt.Errorf("obfs: crypto/rand cover: %w", err)
		}
	}

	// - генерируем random nonce (12 байт, crypto/rand) -
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("obfs: crypto/rand nonce: %w", err)
	}

	// - AEAD Seal: шифруем inner, AAD = nil (нет дополнительных данных) -
	ciphertext := env.aead.Seal(nil, nonce, inner, nil)

	// - собираем blob: nonce || ciphertext (включая tag) -
	blob := make([]byte, 0, NonceSize+len(ciphertext))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	return blob, nil
}

// --> UNWRAP (общая логика) <--

func unwrap(env *envelope, blob []byte) (*Packet, error) {
	if len(blob) < MinBlobSize {
		return nil, ErrBlobTooShort
	}

	// - извлекаем nonce (первые 12 байт) и ciphertext (остальное) -
	nonce := blob[:NonceSize]
	ciphertext := blob[NonceSize:]

	// - AEAD Open: расшифровываем, AAD = nil -
	inner, err := env.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}

	// - парсим inner header (20 байт) -
	if len(inner) < InnerHeaderSize {
		return nil, ErrMalformedInner
	}

	version := inner[0]
	if version != ProtoVersion {
		return nil, ErrBadVersion
	}

	sessionID := binary.BigEndian.Uint64(inner[1:9])
	seq := binary.BigEndian.Uint64(inner[9:17])
	flags := inner[17]
	payloadLen := int(binary.BigEndian.Uint16(inner[18:20]))

	// - проверяем что payload помещается в inner -
	if InnerHeaderSize+payloadLen > len(inner) {
		return nil, ErrMalformedInner
	}

	// - извлекаем payload, cover bytes отбрасываются -
	payload := make([]byte, payloadLen)
	copy(payload, inner[InnerHeaderSize:InnerHeaderSize+payloadLen])

	return &Packet{
		SessionID: sessionID,
		Seq:       seq,
		Flags:     flags,
		Payload:   payload,
	}, nil
}

// --> ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ <--

// MaxOverhead - максимальный overhead для заданной cover policy.
// Пригодится для расчёта MTU: max_payload = network_mtu - 28 - MaxOverhead(cover)
func MaxOverhead(cover CoverConfig) int {
	return NonceSize + InnerHeaderSize + cover.CoverMax + TagSize
}

// randRange - рандомное число [min, max] через crypto/rand. При min >= max вернёт min.
func randRange(min, max int) int {
	if min >= max {
		return min
	}
	span := max - min + 1
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return min
	}
	n := int(binary.BigEndian.Uint32(buf[:])) % span
	return min + n
}
