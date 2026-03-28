<pre align="center">
      ·bg·bz·bg·                          ·bg·bx·bg·
    ·bg·bq·bg·bg·bg·bg·  ╔══════════════╗  ·bg·bg·bg·bg·bg·bg·
    ~~~~~~~~~~~~~~~~~~~~~~║              ║~~~~~~~~~~~~~~~~~~~~~~
    ~~~~~~~~~~~~~~~~~~~~~~║    FANTIK    ║~~~~~~~~~~~~~~~~~~~~~~
    ~~~~~~~~~~~~~~~~~~~~~~║              ║~~~~~~~~~~~~~~~~~~~~~~
    ·bg·bg·bg·bg·bg·bg·  ╚══════════════╝  ·bg·bg·bg·bg·bq·bg·
        ·bg·bx·bg·                          ·bg·bz·bg·
</pre>

# Fantik Core

Криптографическое ядро для обфускации (TCP с оговорками) и UDP трафика. 
Оборачивает пакеты любого протокола (WireGuard, OpenVPN, AmneziaWG и др.) в AEAD-шифрованную оболочку.
На проводе чистый шум ни одного фиксированного байта, ни одной распознаваемой структуры.

## Что существует в этой нише

- Shadowsocks - похожая идея (AEAD обёртка), но его распазнаёт DPI. Static mask для length prefix - слабое место, которое Fantik решает через per-frame HMAC
- obfs4 (Tor) - Elligator2 handshake, но нет encryption длины кадра
- Cloak - TLS mimicry --> тяжелее и сложнее
- Hysteria/TUIC - UDP-over-TCP, но на QUIC --> тяжёлые зависимости
- XRay/VLESS - полноценный прокси-протокол, не библиотека

## Что делает fantik-core полезным

- Это библиотека, а не приложение. Если хочешь свой протокол обернуть в обфускацию fantik-core - это go get и 10 строк кода.
- TCP framing с HMAC-masked длиной.
- Минимализм. Одна зависимость (golang.org/x/crypto), компилируется под MIPS/ARM. Можно засунуть на роутер с 64MB RAM.
- Transport-agnostic ядро. obfs/ работает с []byte. Хочешь UDP - НА, хочешь TCP - НА, хочешь через WebSocket пропустить - kudasai.

## DPI

DPI (Deep Packet Inspection) умеет распознавать VPN-протоколы по характерным заголовкам и блокировать их. 
Fantik скрывает факт использования VPN:

- Все пакеты выглядят как случайные байты (энтропия ~8 бит/байт)
- Нет magic bytes, фиксированных заголовков, fingerprint-ов
- Размеры пакетов рандомизируются "cover bytes"
- Два транспорта: UDP (нативный) и TCP (для сетей блокирующих UDP)

Fantik **не заменяет** криптографию upstream-протокола. Он скрывает его наличие.

## Кому подходит

- Энтузиасты, которые хотят завернуть VPN в обфускацию
- Разработчики VPN решений
- Администраторы VPS и роутеров с OpenWrt
- Все кому нужен лёгкий обфускатор без тяжёлых зависимостей

## Требования

- Go 1.22+
- Зависимость -- `golang.org/x/crypto`
- Работает на Linux, macOS, Windows, OpenWrt (arm/arm64/mips)
- Минимальные ресурсы: 1 CPUcore (1 vCPU), 128 MB RAM

## Установка

```bash
go get github.com/ERITEK/fantik-core@latest
```

## Архитектура

```
┌─────────────────────────────────┐
│      Upstream (WG, OVPN, ...)   │  UDP-пакеты от приложения
├─────────────────────────────────┤
│       obfs  (AEAD ядро)         │  Wrap/Unwrap, cover, replay
│       transport-agnostic        │  работает с []byte
├──────────┬──────────────────────┤
│   UDP    │   TCP                │  транспорт: доставка blob-ов
│          │   (frame/)           │  UDP: 1 датаграм = 1 blob
│          │                      │  TCP: [EncLen][blob] поток
└──────────┴──────────────────────┘
```

Ядро (`obfs/`) не знает про сеть и работает с `[]byte`. Транспорт (`proxy/`, `frame/`)
определяет как `blob` доставляется между клиентом и сервером.

## Пакеты

| Пакет | Назначение |
|-------|-----------|
| `obfs/` | AEAD обёртка (Wrap/Unwrap), HKDF вывод ключей, ReplayWindow |
| `frame/` | TCP framing -- маскировка длин через HMAC-PRF |
| `session/` | Управление сессиями: SessionMap, state machine, seq counters |
| `proxy/` | UDP server + client с keepalive и reconnect |

## Формат пакета

### На проводе (blob)

```
[Nonce 12B][AEAD ciphertext + Tag 16B]
```

Nonce = 12 случайных байт. Ciphertext = зашифрованный inner packet + 16 байт auth tag.
Для наблюдателя весь blob это случайные байты.

### Внутри AEAD (inner packet)

```
[Version 1B][SessionID 8B][Seq 8B][Flags 1B][PayloadLen 2B][Payload 0..N][Cover 0..M]
```

- **Version** - версия wire format (0x02)
- **SessionID** - идентификатор сессии (crypto/rand, генерируется клиентом)
- **Seq** - порядковый номер (с 1, per-direction)
- **Flags** - тип пакета (Data, Keepalive, KeepaliveAck, Close)
- **PayloadLen** - длина payload (big-endian)
- **Payload** - upstream пакет
- **Cover** - случайные байты для рандомизации размера

### TCP framing

```
TCP frame: [EncLen 2B][blob]
EncLen = uint16_be(blob_len) XOR HMAC-SHA256(frame_key, direction || counter)[0:2]
```

На проводе TCP stream это сплошной поток случайных байт. Длина каждого кадра
маскируется уникальным HMAC на основе монотонного счётчика.

## Криптография

- **AEAD**: ChaCha20-Poly1305 (IETF, RFC 8439)
- **Key derivation**: HKDF-SHA256 из общего PSK
- **Три ключа**: client→server, server→client, frame (TCP)
- **Nonce**: 12 случайных байт per packet (crypto/rand)
- **Replay protection**: sliding window 2048 позиций

```
prk       = HKDF-Extract(salt="fantik-core", ikm=PSK)
client_key = HKDF-Expand(prk, info="fantik-core-c2s", len=32)
server_key = HKDF-Expand(prk, info="fantik-core-s2c", len=32)
frame_key  = HKDF-Expand(prk, info="fantik-core-frame", len=32)
```

## Использование

### Пример: шифрование/расшифровка

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/ERITEK/fantik-core/obfs"
)

func main() {
    // 1. Генерируем PSK (общий секрет, >= 16 байт)
    psk := make([]byte, 32)
    rand.Read(psk)

    // 2. Создаём пару ключей
    kp, err := obfs.NewKeyPair(obfs.Config{
        PSK:   psk,
        Cover: obfs.CoverConfig{CoverMin: 4, CoverMax: 64},
    })
    if err != nil {
        log.Fatal(err)
    }

    // 3. Клиент шифрует пакет
    var sessionID uint64 = 0xDEADBEEF
    var seq uint64 = 1
    payload := []byte("hello world")

    blob, err := kp.WrapC2S(sessionID, seq, obfs.FlagData, payload, 0)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Blob: %d байт (payload %d + overhead)\n", len(blob), len(payload))

    // 4. Сервер расшифровывает
    pkt, err := kp.UnwrapC2S(blob)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("SessionID: %x, Seq: %d, Payload: %s\n",
        pkt.SessionID, pkt.Seq, pkt.Payload)
}
```

### UDP proxy (полная цепочка)

```go
package main

import (
    "crypto/rand"
    "log"
    "os"
    "os/signal"
    "time"

    "github.com/ERITEK/fantik-core/obfs"
    "github.com/ERITEK/fantik-core/proxy"
)

func main() {
    psk := make([]byte, 32)
    rand.Read(psk)

    kp, _ := obfs.NewKeyPair(obfs.Config{
        PSK:   psk,
        Cover: obfs.CoverConfig{CoverMin: 4, CoverMax: 64},
    })

    // Сервер (на VPS)
    srv := proxy.NewUDPServer(proxy.UDPServerOpts{
        ListenAddr:   "0.0.0.0:443",
        UpstreamAddr: "127.0.0.1:51820", // WireGuard
        Keys:         kp,
    })
    if err := srv.Start(); err != nil {
        log.Fatal(err)
    }
    defer srv.Stop()

    // Клиент (на локальной машине / роутере)
    client := proxy.NewUDPClient(proxy.UDPClientOpts{
        ListenAddr:        "127.0.0.1:1618",
        ServerAddr:        "your-vps:443",
        Keys:              kp,
        KeepaliveInterval: 15 * time.Second,
    })
    if err := client.Start(); err != nil {
        log.Fatal(err)
    }
    defer client.Stop()

    // Ждём Ctrl+C
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt)
    <-sig
}
```

### TCP framing

```go
package main

import (
    "bufio"
    "crypto/rand"
    "log"
    "net"

    "github.com/ERITEK/fantik-core/frame"
    "github.com/ERITEK/fantik-core/obfs"
)

func main() {
    psk := make([]byte, 32)
    rand.Read(psk)

    kp, _ := obfs.NewKeyPair(obfs.Config{
        PSK:   psk,
        Cover: obfs.CoverConfig{CoverMin: 4, CoverMax: 64},
    })

    // Получаем frame_key из KeyPair
    frameKey := kp.FrameKey()

    // --- Клиент: отправка ---
    conn, _ := net.Dial("tcp", "your-vps:443")
    clientFramer, _ := frame.NewFramer(frameKey)

    // Шифруем payload -> blob
    blob, _ := kp.WrapC2S(0x1234, 1, obfs.FlagData, []byte("hello"), 0)

    // Кодируем blob в TCP кадр и отправляем
    tcpFrame := clientFramer.Encode(blob, frame.DirC2S)
    conn.Write(tcpFrame)

    // --- Сервер: приём ---
    serverFramer, _ := frame.NewFramer(frameKey)
    reader := bufio.NewReaderSize(conn, 8192)

    // Читаем TCP кадр -> blob
    blob, err := serverFramer.ReadFrame(reader, frame.DirC2S, frame.DefaultMaxBlobSize)
    if err != nil {
        log.Fatal(err) // desync -> disconnect
    }

    // Расшифровываем blob -> payload
    pkt, _ := kp.UnwrapC2S(blob)
    log.Printf("Получено: %s", pkt.Payload)
}
```

## Схемы работы

### UDP transport (рекомендуется)

```
Upstream app --UDP--> Fantik client ==UDP==> Fantik server --UDP--> Upstream server
                       (WrapC2S)              (UnwrapC2S)
                       (UnwrapS2C)            (WrapS2C)
```

### TCP transport (для сетей блокирующих UDP)

```
Upstream app --UDP--> Fantik client ==TCP==> Fantik server --UDP--> Upstream server
                       (WrapC2S)              (ReadFrame)
                       (Encode)               (UnwrapC2S)
```

### На роутере с OpenWrt

```
Устройство --UDP--> OpenWrt (Fantik client) ==UDP/TCP==> VPS (Fantik server) --UDP--> WG server
```

Fantik Core компилируется под MIPS/ARM (OpenWrt), потребляет минимум ресурсов.

```bash
# Кросс-компиляция для OpenWrt (пример для MT7621, mips)
GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o fantik-client ./cmd/client/
```

## Overhead

| Компонент | UDP | TCP |
|-----------|-----|-----|
| EncLen | - | 2 |
| Nonce | 12 | 12 |
| Inner header | 20 | 20 |
| AEAD tag | 16 | 16 |
| Cover (avg) | ~34 | ~34 |
| **Per packet** | **~82** | **~84** |

При payload 1280 байт - overhead ~6%.

## Производительность

| Операция | Payload | Время | Аллокации |
|----------|---------|-------|-----------|
| WrapC2S | 148 B | ~31 µs | 5, 650 B |
| UnwrapC2S | 148 B | ~0.7 µs | 3, 404 B |
| WrapC2S | 1200 B | ~33 µs | 5, 3.9 KB |
| UnwrapC2S | 1200 B | ~4 µs | 3, 2.6 KB |
| Frame Encode | 200 B | ~1.2 µs | 8, 736 B |
| Frame ReadFrame | 200 B | ~1.3 µs | 9, 736 B |

Bottleneck Wrap = crypto/rand (генерация nonce + cover).

## Тесты

```bash
go test ./... -v
```

53 теста + 6 бенчмарков, покрытие:

- `obfs/`: roundtrip, direction isolation, tamper, wrong key, MTU clamping, cover variance, replay window
- `frame/`: roundtrip, counter sync 100 кадров, direction isolation, bidirectional, partial reads, desync, randomness EncLen
- `session/`: state machine, seq counters, replay, cleanup, callbacks
- `proxy/`: integration roundtrip, burst 50 пакетов, garbage resistance, state strings

## Безопасность

- PSK более 16 байт (рекомендуется 32 или 64)
- Random nonce per packet (crypto/rand) == нет nonce reuse
- Раздельные ключи per direction == нет key reuse
- Replay window 2048 == защита от replay-атак
- TCP EncLen маскируется per-frame HMAC (не static mask) == устойчивее Shadowsocks
- При любой ошибке TCP framing == disconnect (без попыток ресинхронизации)

## Известные ограничения

- Статический PSK --> при компрометации ==> менять вручную
- TCP: head-of-line blocking (неизбежно для UDP-over-TCP)
- TCP: одно соединение = single point of failure (решение: reconnect, fallback, transport = auto)
- Высокая энтропия без TLS handshake --> DPI может флагировать (решается mimicry)
- Flow fingerprinting (тайминг, burst) --> не решается без traffic shaping

## Лицензия

MIT License

## Авторы

- **ERITEK** : идия, архитектура, код.
- **Loo1** : код, тестирование, комментарии.
- кофе, много кофе. «Черней чернейшей черноты бесконечности!»

## P/S

Это нулевое ядро т.к. проект рождался не для общего пользования, а кор уже отревизирован то выкладываю с чистой совестью.
Многие обвязки и функции вам придётся обдумать самостоятельно. 'понять и простить'
Возможно позже или сильно позже сварганим открытый exe.мпляр (но это будет что то простое) для примера.

### ППС для вайбкодеров

Код написан в лучших традициях яндекс практикум, везде есть комментарий и разберётся даже папич. 
Если прогуливали уроки информатики, то большая просьба загуглить/перплексить все вводные ибо нейронки очень умные и могут творить вещи понятные только им.
