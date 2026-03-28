package session

import (
	"testing"
	"time"
)

// --> SESSION BASIC <--

func TestSessionNew(t *testing.T) {
	sess := New(0x1234)

	if sess.SessionID != 0x1234 {
		t.Errorf("SessionID: got %x, want %x", sess.SessionID, 0x1234)
	}
	if sess.GetState() != StateNew {
		t.Errorf("State: got %v, want NEW", sess.GetState())
	}
	if sess.TxSeq() != 0 {
		t.Errorf("TxSeq: got %d, want 0", sess.TxSeq())
	}
}

func TestSessionTouch(t *testing.T) {
	sess := New(1)

	if sess.GetState() != StateNew {
		t.Fatal("expected NEW")
	}

	sess.Touch()
	if sess.GetState() != StateActive {
		t.Errorf("expected ACTIVE after Touch, got %v", sess.GetState())
	}
}

func TestSessionTouchFromIdle(t *testing.T) {
	sess := New(1)
	sess.SetState(StateIdle)
	sess.Touch()

	if sess.GetState() != StateActive {
		t.Errorf("expected ACTIVE after Touch from IDLE, got %v", sess.GetState())
	}
}

// --> SEQ COUNTERS <--

func TestSessionNextTxSeq(t *testing.T) {
	sess := New(1)

	if seq := sess.NextTxSeq(); seq != 1 {
		t.Errorf("first NextTxSeq: got %d, want 1", seq)
	}
	if seq := sess.NextTxSeq(); seq != 2 {
		t.Errorf("second NextTxSeq: got %d, want 2", seq)
	}
	if seq := sess.NextTxSeq(); seq != 3 {
		t.Errorf("third NextTxSeq: got %d, want 3", seq)
	}
}

// --> REPLAY <--

func TestSessionReplay(t *testing.T) {
	sess := New(1)

	if !sess.CheckAndAcceptSeq(1) {
		t.Error("seq=1 should be accepted")
	}
	if sess.CheckAndAcceptSeq(1) {
		t.Error("seq=1 replay should be rejected")
	}
	if !sess.CheckAndAcceptSeq(2) {
		t.Error("seq=2 should be accepted")
	}
}

// --> CLOSE <--

func TestSessionClose(t *testing.T) {
	sess := New(1)
	sess.Close()

	if !sess.IsClosed() {
		t.Error("expected IsClosed after Close")
	}
	if sess.GetState() != StateClosed {
		t.Errorf("expected CLOSED, got %v", sess.GetState())
	}
}

// --> EXPIRED <--

func TestSessionIsExpired(t *testing.T) {
	sess := New(1)

	if sess.IsExpired(time.Second) {
		t.Error("new session should not be expired")
	}

	// - искусственно сдвигаем LastSeen в прошлое -
	sess.mu.Lock()
	sess.LastSeen = time.Now().Add(-5 * time.Minute)
	sess.mu.Unlock()

	if !sess.IsExpired(2 * time.Minute) {
		t.Error("session should be expired after 5 min with 2 min timeout")
	}
}

// --> STATE STRING <--

func TestStateString(t *testing.T) {
	tests := map[State]string{
		StateNew:     "NEW",
		StateActive:  "ACTIVE",
		StateIdle:    "IDLE",
		StateExpired: "EXPIRED",
		StateClosed:  "CLOSED",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String(): got %q, want %q", s, got, want)
		}
	}
}

// --> SESSION MAP BASIC <--

func TestMapPutGet(t *testing.T) {
	m := NewMap()

	if m.Count() != 0 {
		t.Fatalf("Count: got %d, want 0", m.Count())
	}

	sess := New(0xABCD)
	m.Put(0xABCD, sess)

	if m.Count() != 1 {
		t.Fatalf("Count: got %d, want 1", m.Count())
	}

	got := m.Get(0xABCD)
	if got == nil || got.SessionID != 0xABCD {
		t.Fatal("Get returned wrong session")
	}

	// - несуществующий ID -
	if m.Get(0x9999) != nil {
		t.Error("Get for missing ID should return nil")
	}
}

func TestMapDelete(t *testing.T) {
	m := NewMap()
	m.Put(1, New(1))
	m.Put(2, New(2))

	m.Delete(1)
	if m.Count() != 1 {
		t.Errorf("Count after delete: got %d, want 1", m.Count())
	}
	if m.Get(1) != nil {
		t.Error("deleted session should be nil")
	}
}

// --> MAP CLEANUP <--

func TestMapCleanup(t *testing.T) {
	m := NewMap()

	// - старая сессия (5 минут назад) -
	old := New(1)
	old.mu.Lock()
	old.LastSeen = time.Now().Add(-5 * time.Minute)
	old.mu.Unlock()
	m.Put(1, old)

	// - свежая сессия -
	fresh := New(2)
	m.Put(2, fresh)

	// - закрытая сессия -
	closed := New(3)
	closed.Close()
	m.Put(3, closed)

	removed := m.Cleanup(2*time.Minute, nil)
	if removed != 2 {
		t.Errorf("Cleanup: removed %d, want 2", removed)
	}
	if m.Count() != 1 {
		t.Errorf("Count after cleanup: got %d, want 1", m.Count())
	}
	if m.Get(2) == nil {
		t.Error("fresh session should survive cleanup")
	}
}

func TestMapCleanupCallback(t *testing.T) {
	m := NewMap()

	old := New(1)
	old.mu.Lock()
	old.LastSeen = time.Now().Add(-5 * time.Minute)
	old.mu.Unlock()
	m.Put(1, old)

	var removedIDs []uint64
	m.Cleanup(2*time.Minute, func(s *Session) {
		removedIDs = append(removedIDs, s.SessionID)
	})

	if len(removedIDs) != 1 || removedIDs[0] != 1 {
		t.Errorf("onRemove callback: got %v, want [1]", removedIDs)
	}
}

// --> MAP RANGE <--

func TestMapRange(t *testing.T) {
	m := NewMap()
	m.Put(1, New(1))
	m.Put(2, New(2))
	m.Put(3, New(3))

	count := 0
	m.Range(func(id uint64, sess *Session) bool {
		count++
		return true
	})

	if count != 3 {
		t.Errorf("Range count: got %d, want 3", count)
	}
}

func TestMapRangeBreak(t *testing.T) {
	m := NewMap()
	m.Put(1, New(1))
	m.Put(2, New(2))
	m.Put(3, New(3))

	count := 0
	m.Range(func(id uint64, sess *Session) bool {
		count++
		return false // - прерываем после первого -
	})

	if count != 1 {
		t.Errorf("Range with break: got %d, want 1", count)
	}
}
