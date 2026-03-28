package obfs

// --> REPLAY WINDOW <--
// - скользящее окно для обнаружения повторных пакетов по seq number -
// - используется на сервере (для c2s) и на клиенте (для s2c) -
//
// Как работает:
// Каждый пакет содержит порядковый номер Seq (uint64, с 1).
// ReplayWindow запоминает какие Seq уже были приняты и отклоняет повторные.
// Окно размером 2048 позиций - пакеты с Seq старше чем (maxSeq - 2048) отклоняются.
//
// Типичное использование:
//
//	rw := obfs.NewReplayWindow()
//
//	// При получении пакета:
//	if !rw.CheckAndAccept(pkt.Seq) {
//	    // replay или слишком старый пакет - дроп
//	    continue
//	}
//	// пакет принят, обрабатываем
//
// !!! ВНИМАНИЕ ёпта !!! ReplayWindow НЕ потокобезопасен.
// Вызывающий код должен защищать его мьютексом (или использовать один ReplayWindow строго из одной горутины).
// ReplayWindowSize - размер окна в позициях.
// 2048 позиций покрывают стандартные сценарии переупорядочивания пакетов в UDP.
const ReplayWindowSize = 2048

// ReplayWindow - скользящее окно для replay protection.
// Bitmap на массиве uint64, покрывает ReplayWindowSize позиций.
type ReplayWindow struct {
	maxSeq uint64
	bitmap [ReplayWindowSize / 64]uint64
}

// NewReplayWindow - создаёт пустое окно. Готово к приёму пакетов.
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// Check - можно ли принять пакет с этим seq? true = норм, false = replay/старый.
// ! -> Состояние не меняет, для фиксации вызывай Accept().
//
// seq=0 отклоняется всегда (нумерация с 1).
// seq > maxSeq принимается всегда.
// seq в окне и не видели - ок. Уже видели - replay.
// seq старше окна (diff >= 2048) - дроп.
func (rw *ReplayWindow) Check(seq uint64) bool {
	// - seq=0 невалиден (нумерация с 1) -
	if seq == 0 {
		return false
	}

	// - первый пакет -
	if rw.maxSeq == 0 {
		return true
	}

	// - новый seq больше текущего максимума - всегда ок -
	if seq > rw.maxSeq {
		return true
	}

	// - seq <= maxSeq: проверяем что попадает в окно -
	diff := rw.maxSeq - seq
	if diff >= ReplayWindowSize {
		return false // - слишком старый -
	}

	// - проверяем бит в bitmap: 0 = не видели, 1 = уже видели -
	wordIdx := diff / 64
	bitIdx := diff % 64
	return (rw.bitmap[wordIdx] & (1 << bitIdx)) == 0
}

// Accept - фиксирует seq как принятый, обновляет состояние окна.
// Вызывать только после успешного Check().
func (rw *ReplayWindow) Accept(seq uint64) {
	if rw.maxSeq == 0 || seq > rw.maxSeq {
		// - сдвигаем окно вперёд -
		if rw.maxSeq > 0 {
			shift := seq - rw.maxSeq
			rw.shiftBitmap(shift)
		}
		rw.maxSeq = seq
		// - помечаем текущий seq (позиция 0 в bitmap) -
		rw.bitmap[0] |= 1
	} else {
		// - seq в пределах окна - помечаем как seen -
		diff := rw.maxSeq - seq
		wordIdx := diff / 64
		bitIdx := diff % 64
		rw.bitmap[wordIdx] |= (1 << bitIdx)
	}
}

// CheckAndAccept - атомарная проверка + принятие.
// Возвращает true если пакет принят, false если replay/слишком старый.
func (rw *ReplayWindow) CheckAndAccept(seq uint64) bool {
	if !rw.Check(seq) {
		return false
	}
	rw.Accept(seq)
	return true
}

// Reset - сбрасывает окно в начальное состояние.
// Полезно при смене сессии (новый SessionID -> новое окно).
func (rw *ReplayWindow) Reset() {
	rw.maxSeq = 0
	for i := range rw.bitmap {
		rw.bitmap[i] = 0
	}
}

// - shiftBitmap - сдвигает bitmap на shift позиций вправо -
func (rw *ReplayWindow) shiftBitmap(shift uint64) {
	if shift >= ReplayWindowSize {
		// - полный сброс: все старые позиции за пределами окна -
		for i := range rw.bitmap {
			rw.bitmap[i] = 0
		}
		return
	}

	wordShift := shift / 64
	bitShift := shift % 64

	// - сдвиг по словам (uint64 блоками) -
	if wordShift > 0 {
		for i := len(rw.bitmap) - 1; i >= 0; i-- {
			if int(wordShift) <= i {
				rw.bitmap[i] = rw.bitmap[i-int(wordShift)]
			} else {
				rw.bitmap[i] = 0
			}
		}
	}

	// - сдвиг по битам внутри слов -
	if bitShift > 0 {
		for i := len(rw.bitmap) - 1; i >= 0; i-- {
			rw.bitmap[i] <<= bitShift
			if i > 0 {
				rw.bitmap[i] |= rw.bitmap[i-1] >> (64 - bitShift)
			}
		}
	}
}
