// Пакет proxy - сетевые прокси для Fantik (UDP transport).
//
// UDPServer принимает AEAD blob от клиентов, расшифровывает, маршрутизирует payload по SessionID к upstream и обратно.
//
// UDPClient слушает upstream пакеты от локального приложения, оборачивает в AEAD blob и отправляет на сервер. 
// Ответы от сервера расшифровывает и возвращает upstream приложению.
//
// ! Rate limiting, session flood protection ЭТО ответственность прикладного кода !
// Этот пакет реализует только протокольную логику.
package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ERITEK/fantik-core/obfs"
	"github.com/ERITEK/fantik-core/session"
)

// --> КОНФИГУРАЦИЯ UDP СЕРВЕРА <--

// UDPServerOpts - параметры для создания UDP сервера.
//
// Пример:
//
//	srv := proxy.NewUDPServer(proxy.UDPServerOpts{
//	    ListenAddr:     "0.0.0.0:443",
//	    UpstreamAddr:   "127.0.0.1:51820",
//	    Keys:           kp,
//	    MaxPacket:      1472,
//	    SessionTimeout: 120 * time.Second,
//	})
type UDPServerOpts struct {
	ListenAddr     string         // - адрес:порт для приёма blob от клиентов -
	UpstreamAddr   string         // - адрес:порт upstream (куда пересылать расшифрованные пакеты) -
	Keys           *obfs.KeyPair  // - ключи AEAD -
	MaxPacket      int            // - макс размер UDP пакета, обычно 1472 (1500 - 28) -
	BufSize        int            // - размер буфера чтения (0 = 65535) -
	SessionTimeout time.Duration  // - таймаут неактивной сессии (0 = 120 сек) -
	CleanupInterval time.Duration // - интервал чистки сессий (0 = 30 сек) -

	// OnNewSession - callback при создании новой сессии.
	// Прикладной код может использовать для rate limit, логирования и т.д.
	// Если вернёт false -> сессия не создаётся (пакет дропается).
	// nil = всегда разрешать.
	OnNewSession func(sessionID uint64, clientAddr *net.UDPAddr) bool
}

// --> UDP SERVER <--

// UDPServer - UDP proxy сервер.
//
// Цепочка обработки входящего пакета:
//  1. ReadFromUDP -> blob
//  2. Pre-filter: проверка размера
//  3. UnwrapC2S -> Packet (SessionID, Seq, Flags, Payload)
//  4. Lookup/create Session
//  5. Replay check
//  6. Dispatch: Data -> upstream, Keepalive -> ack, Close -> удаление
//
// Обратный путь (upstream -> клиент):
//  1. upstream.Read -> payload
//  2. WrapS2C -> blob
//  3. WriteToUDP -> клиенту
type UDPServer struct {
	opts      UDPServerOpts
	sessions  *session.Map
	listener  *net.UDPConn
	upAddr    *net.UDPAddr

	// - транспортные данные сессий (upstream conn + client addr) -
	transportMu sync.RWMutex
	transport   map[uint64]*serverSessionTransport

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// - serverSessionTransport - транспортные данные одной сессии на сервере -
type serverSessionTransport struct {
	clientAddr *net.UDPAddr // - последний известный адрес клиента -
	serverConn *net.UDPConn // - серверный listener (для WriteToUDP) -
	upConn     *net.UDPConn // - выделенный upstream conn -
}

// NewUDPServer - создаёт UDP сервер. Не запускает - для старта вызови Start().
func NewUDPServer(opts UDPServerOpts) *UDPServer {
	if opts.BufSize <= 0 {
		opts.BufSize = 65535
	}
	if opts.MaxPacket <= 0 {
		opts.MaxPacket = 1472
	}
	if opts.SessionTimeout <= 0 {
		opts.SessionTimeout = session.DefaultSessionTimeout
	}
	if opts.CleanupInterval <= 0 {
		opts.CleanupInterval = session.DefaultCleanupInterval
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &UDPServer{
		opts:      opts,
		sessions:  session.NewMap(),
		transport: make(map[uint64]*serverSessionTransport),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start - запускает сервер: слушает UDP, принимает пакеты, чистит сессии.
func (s *UDPServer) Start() error {
	upAddr, err := net.ResolveUDPAddr("udp4", s.opts.UpstreamAddr)
	if err != nil {
		return fmt.Errorf("proxy/server: resolve upstream %q: %w", s.opts.UpstreamAddr, err)
	}
	s.upAddr = upAddr

	listenAddr, err := net.ResolveUDPAddr("udp4", s.opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("proxy/server: resolve listen %q: %w", s.opts.ListenAddr, err)
	}
	s.listener, err = net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return fmt.Errorf("proxy/server: listen %s: %w", s.opts.ListenAddr, err)
	}
	log.Printf("proxy/server: listen=%s upstream=%s", s.listener.LocalAddr(), s.opts.UpstreamAddr)

	s.wg.Add(2)
	go s.fromClientLoop()
	go s.cleanupLoop()
	return nil
}

// Stop - останавливает сервер, закрывает все соединения.
func (s *UDPServer) Stop() {
	s.cancel()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	// - закрываем все upstream conn -
	s.sessions.Cleanup(0, func(sess *session.Session) {
		s.closeTransport(sess.SessionID)
	})
	s.wg.Wait()
}

// SessionCount - количество активных сессий.
func (s *UDPServer) SessionCount() int {
	return s.sessions.Count()
}

// --> ПРИЁМ ОТ КЛИЕНТОВ <--

func (s *UDPServer) fromClientLoop() {
	defer s.wg.Done()
	buf := make([]byte, s.opts.BufSize)

	for {
		n, clientAddr, err := s.listener.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}

		// - pre-filter: размер -
		if n < obfs.MinBlobSize || n > s.opts.MaxPacket {
			continue
		}

		blob := make([]byte, n)
		copy(blob, buf[:n])

		// - AEAD unwrap -
		pkt, err := s.opts.Keys.UnwrapC2S(blob)
		if err != nil {
			continue
		}

		// - lookup / create session -
		sess := s.sessions.Get(pkt.SessionID)
		if sess == nil {
			// - callback для rate limit / flood protection -
			if s.opts.OnNewSession != nil && !s.opts.OnNewSession(pkt.SessionID, clientAddr) {
				continue
			}

			upConn, err := net.DialUDP("udp4", nil, s.upAddr)
			if err != nil {
				log.Printf("proxy/server: dial upstream session=%x: %v", pkt.SessionID, err)
				continue
			}

			sess = session.New(pkt.SessionID)
			s.sessions.Put(pkt.SessionID, sess)
			s.setTransport(pkt.SessionID, &serverSessionTransport{
				clientAddr: clientAddr,
				serverConn: s.listener,
				upConn:     upConn,
			})

			s.wg.Add(1)
			go s.fromUpstreamLoop(pkt.SessionID)
		} else {
			s.updateClientAddr(pkt.SessionID, clientAddr)
		}

		sess.Touch()

		// - replay check -
		if !sess.CheckAndAcceptSeq(pkt.Seq) {
			continue
		}

		// - dispatch -
		switch {
		case pkt.Flags&obfs.FlagKeepalive != 0:
			s.sendKeepaliveAck(pkt.SessionID, sess)

		case pkt.Flags&obfs.FlagClose != 0:
			sess.Close()
			s.closeTransport(pkt.SessionID)
			s.sessions.Delete(pkt.SessionID)

		case pkt.Flags&obfs.FlagData != 0:
			if len(pkt.Payload) > 0 {
				tr := s.getTransport(pkt.SessionID)
				if tr != nil && tr.upConn != nil {
					_, _ = tr.upConn.Write(pkt.Payload)
				}
			}
		}
	}
}

// --> ПРИЁМ ОТ UPSTREAM <--

func (s *UDPServer) fromUpstreamLoop(sessionID uint64) {
	defer s.wg.Done()
	buf := make([]byte, s.opts.BufSize)

	tr := s.getTransport(sessionID)
	if tr == nil {
		return
	}

	for {
		n, err := tr.upConn.Read(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			return
		}

		sess := s.sessions.Get(sessionID)
		if sess == nil {
			return
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		seq := sess.NextTxSeq()
		blob, err := s.opts.Keys.WrapS2C(sessionID, seq, obfs.FlagData, payload, s.opts.MaxPacket)
		if err != nil {
			continue
		}

		tr = s.getTransport(sessionID)
		if tr != nil && tr.clientAddr != nil && tr.serverConn != nil {
			_, _ = tr.serverConn.WriteToUDP(blob, tr.clientAddr)
		}
	}
}

// - отправляет keepalive ACK клиенту -
func (s *UDPServer) sendKeepaliveAck(sessionID uint64, sess *session.Session) {
	seq := sess.NextTxSeq()
	blob, err := s.opts.Keys.WrapS2C(sessionID, seq, obfs.FlagKeepaliveAck, nil, s.opts.MaxPacket)
	if err != nil {
		return
	}
	tr := s.getTransport(sessionID)
	if tr != nil && tr.clientAddr != nil && tr.serverConn != nil {
		_, _ = tr.serverConn.WriteToUDP(blob, tr.clientAddr)
	}
}

// --> CLEANUP <--

func (s *UDPServer) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.opts.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			removed := s.sessions.Cleanup(s.opts.SessionTimeout, func(sess *session.Session) {
				s.closeTransport(sess.SessionID)
			})
			if removed > 0 {
				log.Printf("proxy/server: cleaned %d sessions, active: %d", removed, s.sessions.Count())
			}
		}
	}
}

// --> TRANSPORT HELPERS <--

func (s *UDPServer) setTransport(id uint64, tr *serverSessionTransport) {
	s.transportMu.Lock()
	defer s.transportMu.Unlock()
	s.transport[id] = tr
}

func (s *UDPServer) getTransport(id uint64) *serverSessionTransport {
	s.transportMu.RLock()
	defer s.transportMu.RUnlock()
	return s.transport[id]
}

func (s *UDPServer) updateClientAddr(id uint64, addr *net.UDPAddr) {
	s.transportMu.Lock()
	defer s.transportMu.Unlock()
	if tr, ok := s.transport[id]; ok {
		tr.clientAddr = addr
	}
}

func (s *UDPServer) closeTransport(id uint64) {
	s.transportMu.Lock()
	defer s.transportMu.Unlock()
	if tr, ok := s.transport[id]; ok {
		if tr.upConn != nil {
			_ = tr.upConn.Close()
		}
		delete(s.transport, id)
	}
}
