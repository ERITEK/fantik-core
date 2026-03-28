package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ERITEK/fantik-core/obfs"
	oReplay "github.com/ERITEK/fantik-core/obfs"
)

// --> СОСТОЯНИЯ КЛИЕНТА <--
// - state machine: IDLE -> STARTING -> ESTABLISHED -> DEGRADED -> RECONNECTING -> CLOSED -

// ClientState - текущее состояние клиента.
type ClientState int

const (
	ClientIdle         ClientState = iota // - не запущен -
	ClientStarting                        // - запущен, ждём первый пакет/ack -
	ClientEstablished                     // - связь работает -
	ClientDegraded                        // - пропущены keepalive (>=2) -
	ClientReconnecting                    // - пропущены keepalive (>=5), пересоздаём сессию -
	ClientClosed                          // - остановлен -
)

// String - строковое представление состояния (для логов).
func (s ClientState) String() string {
	switch s {
	case ClientIdle:
		return "IDLE"
	case ClientStarting:
		return "STARTING"
	case ClientEstablished:
		return "ESTABLISHED"
	case ClientDegraded:
		return "DEGRADED"
	case ClientReconnecting:
		return "RECONNECTING"
	case ClientClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// --> КОНФИГУРАЦИЯ UDP КЛИЕНТА <--

// UDPClientOpts - параметры для создания UDP клиента.
//
// Пример:
//
//	client := proxy.NewUDPClient(proxy.UDPClientOpts{
//	    ListenAddr:        "127.0.0.1:1618",
//	    ServerAddr:        "1.2.3.4:443",
//	    Keys:              kp,
//	    MaxPacket:         1472,
//	    KeepaliveInterval: 15 * time.Second,
//	})
type UDPClientOpts struct {
	ListenAddr        string         // - адрес:порт для приёма пакетов от upstream -
	ServerAddr        string         // - адрес:порт сервера Fantik -
	Keys              *obfs.KeyPair  // - ключи AEAD -
	MaxPacket         int            // - макс размер blob (0 = 1472) -
	BufSize           int            // - размер буфера чтения (0 = 65535) -
	KeepaliveInterval time.Duration  // - интервал keepalive (0 = 15 сек) -
	MaxSessionPackets uint64         // - ротация сессии после N пакетов (0 = 2^30) -
}

// --> UDP CLIENT <--

// UDPClient - UDP proxy клиент.
//
// Цепочка:
//
//	upstream app -> [UDP] -> UDPClient -> [WrapC2S] -> [UDP] -> сервер
//	сервер -> [UDP] -> UDPClient -> [UnwrapS2C] -> [UDP] -> upstream app
//
// Keepalive: клиент периодически отправляет FlagKeepalive, ожидает FlagKeepaliveAck.
// При 2 пропущенных ack -> DEGRADED, при 5 -> RECONNECTING (новый SessionID).
type UDPClient struct {
	opts       UDPClientOpts
	localConn  *net.UDPConn
	remote     *net.UDPConn
	serverAddr *net.UDPAddr

	// - адрес upstream приложения (для обратных пакетов) -
	lastLocalMu   sync.RWMutex
	lastLocalAddr *net.UDPAddr

	// - session -
	sessionMu sync.RWMutex
	sessionID uint64
	txSeq     atomic.Uint64
	replay    *oReplay.ReplayWindow

	// - state -
	stateMu   sync.RWMutex
	state     ClientState
	startTime time.Time

	// - keepalive tracking -
	lastKASent atomic.Int64
	lastKAAck  atomic.Int64
	missedKA   atomic.Int32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewUDPClient - создаёт UDP клиент. Не запускает - для старта вызови Start().
func NewUDPClient(opts UDPClientOpts) *UDPClient {
	if opts.BufSize <= 0 {
		opts.BufSize = 65535
	}
	if opts.MaxPacket <= 0 {
		opts.MaxPacket = 1472
	}
	if opts.KeepaliveInterval <= 0 {
		opts.KeepaliveInterval = 15 * time.Second
	}
	if opts.MaxSessionPackets == 0 {
		opts.MaxSessionPackets = 1 << 30
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &UDPClient{
		opts:   opts,
		replay: oReplay.NewReplayWindow(),
		state:  ClientIdle,
		ctx:    ctx,
		cancel: cancel,
	}
	c.generateSessionID()
	return c
}

// Start - запускает клиент: слушает upstream, отправляет на сервер, keepalive.
func (c *UDPClient) Start() error {
	serverAddr, err := net.ResolveUDPAddr("udp4", c.opts.ServerAddr)
	if err != nil {
		return fmt.Errorf("proxy/client: resolve server %q: %w", c.opts.ServerAddr, err)
	}
	c.serverAddr = serverAddr

	listenAddr, err := net.ResolveUDPAddr("udp4", c.opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("proxy/client: resolve listen %q: %w", c.opts.ListenAddr, err)
	}
	c.localConn, err = net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return fmt.Errorf("proxy/client: listen %s: %w", c.opts.ListenAddr, err)
	}

	c.remote, err = net.ListenUDP("udp4", nil)
	if err != nil {
		c.localConn.Close()
		return fmt.Errorf("proxy/client: remote socket: %w", err)
	}

	log.Printf("proxy/client: listen=%s server=%s session=%x",
		c.localConn.LocalAddr(), c.opts.ServerAddr, c.getSessionID())

	c.setState(ClientStarting)
	c.startTime = time.Now()

	c.wg.Add(3)
	go c.fromLocalLoop()
	go c.fromServerLoop()
	go c.keepaliveLoop()

	return nil
}

// Stop - останавливает клиент, отправляет FlagClose серверу.
func (c *UDPClient) Stop() {
	c.sendClose()
	c.cancel()
	if c.localConn != nil {
		c.localConn.Close()
	}
	if c.remote != nil {
		c.remote.Close()
	}
	c.wg.Wait()
	c.setState(ClientClosed)
}

// --> UPSTREAM -> SERVER <--

func (c *UDPClient) fromLocalLoop() {
	defer c.wg.Done()
	buf := make([]byte, c.opts.BufSize)

	for {
		n, addr, err := c.localConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		c.lastLocalMu.Lock()
		c.lastLocalAddr = addr
		c.lastLocalMu.Unlock()

		sid := c.getSessionID()
		seq := c.txSeq.Add(1)

		// - ротация сессии по счётчику пакетов -
		if seq >= c.opts.MaxSessionPackets {
			c.doReconnect()
			sid = c.getSessionID()
			seq = c.txSeq.Add(1)
		}

		blob, err := c.opts.Keys.WrapC2S(sid, seq, obfs.FlagData, payload, c.opts.MaxPacket)
		if err != nil {
			continue
		}

		if _, err := c.remote.WriteToUDP(blob, c.serverAddr); err != nil {
			log.Printf("proxy/client: write server: %v", err)
		}

		if c.GetState() == ClientStarting {
			c.setState(ClientEstablished)
		}
	}
}

// --> SERVER -> UPSTREAM <--

func (c *UDPClient) fromServerLoop() {
	defer c.wg.Done()
	buf := make([]byte, c.opts.BufSize)

	for {
		n, _, err := c.remote.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			continue
		}

		blob := make([]byte, n)
		copy(blob, buf[:n])

		pkt, err := c.opts.Keys.UnwrapS2C(blob)
		if err != nil {
			continue
		}

		// - replay check -
		if !c.replay.CheckAndAccept(pkt.Seq) {
			continue
		}

		switch {
		case pkt.Flags&obfs.FlagKeepaliveAck != 0:
			c.lastKAAck.Store(time.Now().UnixNano())
			c.missedKA.Store(0)
			st := c.GetState()
			if st == ClientDegraded || st == ClientReconnecting {
				c.setState(ClientEstablished)
			}

		case pkt.Flags&obfs.FlagData != 0:
			if len(pkt.Payload) == 0 {
				continue
			}
			c.lastLocalMu.RLock()
			dst := c.lastLocalAddr
			c.lastLocalMu.RUnlock()
			if dst == nil {
				continue
			}
			if _, err := c.localConn.WriteToUDP(pkt.Payload, dst); err != nil {
				log.Printf("proxy/client: write upstream: %v", err)
			}
			if c.GetState() == ClientStarting {
				c.setState(ClientEstablished)
			}
		}
	}
}

// --> KEEPALIVE <--

func (c *UDPClient) keepaliveLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.opts.KeepaliveInterval)
	defer ticker.Stop()

	halfInterval := c.opts.KeepaliveInterval / 2

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.sendKeepalive()
			time.AfterFunc(halfInterval, func() {
				select {
				case <-c.ctx.Done():
					return
				default:
				}
				c.checkKeepaliveHealth()
			})
		}
	}
}

func (c *UDPClient) sendKeepalive() {
	sid := c.getSessionID()
	seq := c.txSeq.Add(1)
	blob, err := c.opts.Keys.WrapC2S(sid, seq, obfs.FlagKeepalive, nil, c.opts.MaxPacket)
	if err != nil {
		return
	}
	_, _ = c.remote.WriteToUDP(blob, c.serverAddr)
	c.lastKASent.Store(time.Now().UnixNano())
}

func (c *UDPClient) sendClose() {
	sid := c.getSessionID()
	seq := c.txSeq.Add(1)
	blob, err := c.opts.Keys.WrapC2S(sid, seq, obfs.FlagClose, nil, c.opts.MaxPacket)
	if err != nil {
		return
	}
	if c.remote != nil && c.serverAddr != nil {
		_, _ = c.remote.WriteToUDP(blob, c.serverAddr)
	}
}

func (c *UDPClient) checkKeepaliveHealth() {
	sent := c.lastKASent.Load()
	ack := c.lastKAAck.Load()
	if sent == 0 {
		return
	}
	if ack < sent {
		missed := c.missedKA.Add(1)
		if missed >= 5 {
			c.setState(ClientReconnecting)
		} else if missed >= 2 {
			c.setState(ClientDegraded)
		}
	}
}

// --> RECONNECT <--

func (c *UDPClient) doReconnect() {
	c.sendClose()
	c.generateSessionID()
	c.missedKA.Store(0)
	c.lastKAAck.Store(0)
	c.lastKASent.Store(0)
}

func (c *UDPClient) generateSessionID() {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	c.sessionMu.Lock()
	c.sessionID = binary.BigEndian.Uint64(buf[:])
	c.sessionMu.Unlock()
	c.txSeq.Store(0)
	c.replay = oReplay.NewReplayWindow()
}

// --> STATE <--

func (c *UDPClient) setState(s ClientState) {
	c.stateMu.Lock()
	old := c.state
	c.state = s
	c.stateMu.Unlock()
	if old != s {
		log.Printf("proxy/client: state %s -> %s", old, s)
	}
}

// --> ПУБЛИЧНЫЕ ГЕТТЕРЫ <--

// GetState - текущее состояние клиента.
func (c *UDPClient) GetState() ClientState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

// GetSessionID - текущий SessionID.
func (c *UDPClient) GetSessionID() uint64 {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.sessionID
}

func (c *UDPClient) getSessionID() uint64 {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.sessionID
}

// GetStartTime - время запуска клиента.
func (c *UDPClient) GetStartTime() time.Time {
	return c.startTime
}

// GetMissedKeepalives - количество пропущенных keepalive ack подряд.
func (c *UDPClient) GetMissedKeepalives() int32 {
	return c.missedKA.Load()
}

// GetLastKeepaliveAck - время последнего полученного keepalive ack.
func (c *UDPClient) GetLastKeepaliveAck() time.Time {
	ns := c.lastKAAck.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}
