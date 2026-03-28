// Пакет session - управление сессиями Fantik.
//
// Сессия - это связь между клиентом и сервером, идентифицируемая SessionID
// (8 байт, crypto/rand). Каждая сессия хранит:
//   - состояние (NEW -> ACTIVE -> IDLE -> EXPIRED/CLOSED)
//   - счётчик исходящих seq (для Wrap)
//   - ReplayWindow входящих seq (для защиты от replay)
//   - время создания и последней активности
//
// SessionMap - потокобезопасная карта сессий. Ключ = SessionID (uint64).
//
// Этот пакет 'агностик' == не знает про UDP, TCP, адреса.
// Прикладной код (proxy, server, client) оборачивает Session в свои структуры с транспортными полями.
//
// Типичное использование (сервер):
//
//	sm := session.NewMap()
//
//	// При получении пакета:
//	sess := sm.Get(pkt.SessionID)
//	if sess == nil {
//	    sess = session.New(pkt.SessionID)
//	    sm.Put(pkt.SessionID, sess)
//	}
//	sess.Touch()
//
//	// Периодическая чистка:
//	removed := sm.Cleanup(120 * time.Second)
//
// Типичное использование (клиент):
//
//	sess := session.New(mySessionID)
//	seq := sess.NextTxSeq()        // для WrapC2S
//	ok := sess.CheckAndAcceptSeq(pkt.Seq) // для UnwrapS2C
package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ERITEK/fantik-core/obfs"
)

// --> СОСТОЯНИЯ СЕССИИ <--
// - state machine: NEW -> ACTIVE -> IDLE -> EXPIRED | CLOSED -

// State - текущее состояние сессии.
type State int

const (
	StateNew     State = iota // - только создана, ещё нет data пакетов -
	StateActive               // - получен хотя бы один data пакет -
	StateIdle                 // - нет трафика, но keepalive жив -
	StateExpired              // - timeout, пора удалять -
	StateClosed               // - получен FlagClose или закрыта вручную -
)

// String - строковое представление состояния (для логов).
func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateActive:
		return "ACTIVE"
	case StateIdle:
		return "IDLE"
	case StateExpired:
		return "EXPIRED"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// --> ТАЙМИНГИ ПО УМОЛЧАНИЮ <--

const (
	// DefaultSessionTimeout - время жизни неактивной сессии (120 сек).
	// После этого сессия удаляется при Cleanup().
	DefaultSessionTimeout = 120 * time.Second

	// DefaultCleanupInterval - периодичность вызова Cleanup() (30 сек).
	DefaultCleanupInterval = 30 * time.Second

	// DefaultIdleThreshold - порог перехода ACTIVE -> IDLE (30 сек).
	DefaultIdleThreshold = 30 * time.Second
)

// --> SESSION <--

// Session - одна сессия обфускации.
// Хранит протокольное состояние: seq, replay, state, timestamps.
// ! Транспортные данные (адреса, conn) ЭТО ответственность прикладного кода !
//
// Потокобезопасность: методы Session защищены внутренним мьютексом.
type Session struct {
	mu sync.RWMutex

	// SessionID - уникальный идентификатор (8 байт, генерируется клиентом).
	SessionID uint64

	// State - текущее состояние сессии.
	CurState State

	// Временные метки.
	LastSeen  time.Time
	CreatedAt time.Time

	// txSeq - счётчик исходящих пакетов (атомарный, начинается с 0).
	// NextTxSeq() возвращает значение начиная с 1.
	txSeq atomic.Uint64

	// replay - окно replay protection для входящих пакетов.
	replay *obfs.ReplayWindow
}

// New - создаёт новую сессию с указанным SessionID.
// Состояние = StateNew, seq = 0, replay window пустое.
func New(sessionID uint64) *Session {
	now := time.Now()
	return &Session{
		SessionID: sessionID,
		CurState:  StateNew,
		LastSeen:  now,
		CreatedAt: now,
		replay:    obfs.NewReplayWindow(),
	}
}

// Touch - обновляет LastSeen, переводит в ACTIVE если была NEW или IDLE.
// Вызывается при каждом полученном валидном пакете.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSeen = time.Now()
	if s.CurState == StateNew || s.CurState == StateIdle {
		s.CurState = StateActive
	}
}

// NextTxSeq - следующий порядковый номер для исходящего пакета.
// Начинается с 1, инкрементируется атомарно. Потокобезопасен без мьютекса.
func (s *Session) NextTxSeq() uint64 {
	return s.txSeq.Add(1)
}

// TxSeq - текущее значение счётчика (для чтения, без инкремента).
func (s *Session) TxSeq() uint64 {
	return s.txSeq.Load()
}

// CheckAndAcceptSeq - replay check + accept для входящего seq.
// Возвращает true если пакет принят, false если replay/слишком старый.
// Потокобезопасен (внутренний мьютекс).
func (s *Session) CheckAndAcceptSeq(seq uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replay.CheckAndAccept(seq)
}

// GetState - текущее состояние сессии. Потокобезопасен.
func (s *Session) GetState() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurState
}

// SetState - устанавливает состояние сессии.
func (s *Session) SetState(state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurState = state
}

// Close - переводит сессию в StateClosed.
// ! Прикладной код должен дополнительно закрыть свои транспортные ресурсы !
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurState = StateClosed
}

// IsExpired - проверяет, прошло ли больше timeout с последнего пакета.
func (s *Session) IsExpired(timeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastSeen) > timeout
}

// IsClosed - проверяет, закрыта ли сессия.
func (s *Session) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurState == StateClosed
}

// --> SESSION MAP <--

// Map - потокобезопасная карта сессий. Ключ = SessionID (uint64).
// Используется на сервере для хранения всех активных сессий.
// Клиент обычно работает с одной Session напрямую.
type Map struct {
	mu       sync.RWMutex
	sessions map[uint64]*Session
}

// NewMap - создаёт пустую карту сессий.
func NewMap() *Map {
	return &Map{sessions: make(map[uint64]*Session)}
}

// Get - возвращает сессию по ID или nil если не найдена.
func (m *Map) Get(id uint64) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// Put - добавляет или заменяет сессию.
func (m *Map) Put(id uint64, sess *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = sess
}

// Delete - удаляет сессию по ID.
func (m *Map) Delete(id uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// Count - количество сессий в карте.
func (m *Map) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Cleanup - удаляет просроченные (timeout) и закрытые сессии.
// Возвращает количество удалённых. Вызывайте периодически (раз в 30 сек).
//
// Перед удалением вызывает onRemove callback (если передан) это для закрытия транспортных ресурсов прикладного кода. 
// Если onRemove = nil - просто удаляет.
func (m *Map) Cleanup(timeout time.Duration, onRemove func(*Session)) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	removed := 0
	for id, sess := range m.sessions {
		expired := sess.IsExpired(timeout)
		closed := sess.IsClosed()

		if expired || closed {
			if onRemove != nil {
				onRemove(sess)
			}
			sess.Close()
			delete(m.sessions, id)
			removed++
		}
	}
	return removed
}

// Range - вызывает fn для каждой сессии. Если fn вернёт false - прерывает обход.
// Удерживает RLock на время обхода.
func (m *Map) Range(fn func(id uint64, sess *Session) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, sess := range m.sessions {
		if !fn(id, sess) {
			break
		}
	}
}
