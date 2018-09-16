package ratchet

// RatchetRing:
// Three ratchets, one past, one current, one future.
//
// CounterPast := ((timeNow - StartDate)/duration)
// CounterCurrent := ((timeNow - StartDate)/duration)+1
// CounterFuture := ((timeNow - StartDate)/duration)+2

// RatchetRing contains three ratchets, one current, one past, one future.
type RatchetRing struct {
	past, current, future *RatchetState
}

// NewRatchetRing returns a new, possibly filled, RatchetRing. pastStep is the expected
// counter value for the past value. Operates on a copy of ratchet.
func NewRatchetRing(ratchet *RatchetState, currentStep uint64) *RatchetRing {
	rr := new(RatchetRing)
	rr.set(ratchet, currentStep)
	return rr
}

// set ring to given currentStep, using a copy of ratchet.
func (rr *RatchetRing) set(ratchet *RatchetState, currentStep uint64) {
	r := ratchet.Copy()
	c := r.Counter()
	if c > currentStep {
		// Bad, this means we have a wrong time setting.
		panic("github.com/JonathanLogan/cypherlock/ratchet: Time has reversed or overflown.")
	}
	if c < currentStep {
		for i := c; i < currentStep; i = r.Counter() {
			r.Step()
		}
		rr.past = r.Copy()
		r.Step()
	}
	rr.current = r.Copy()
	// Advance one more for future.
	rr.future = rr.current.Copy().Step()
}

func (rr *RatchetRing) StepTo(currentStep uint64) {
	c := rr.current.Counter()
	if c == currentStep {
		return
	}
	if c == currentStep-1 {
		rr.Step()
		return
	}
	rr.set(rr.current, currentStep)
}

// Execute one step for the ratchets.
func (rr *RatchetRing) Step() {
	rr.past = rr.current.Copy()   // current is ALWAYS set.
	rr.current = rr.future.Copy() // future is ALWAYS set.
	rr.future.Step()              // continue on future.
}

// Current returns a copy of the Current Ratchet State for Marshalling.
// The past state will be lost in marshalling.
func (rr *RatchetRing) Current() *RatchetState {
	return rr.current.Copy()
}

// CurrentStep returns the counter of the current ratchet.
func (rr *RatchetRing) CurrentStep() uint64 {
	return rr.current.Counter()
}

// Find the RatchetState that matches the expected public key and return a copy, or nil
// if not found.
func (rr *RatchetRing) Find(expect *[32]byte) *RatchetState {
	if rr.current != nil && rr.current.PublicKey == *expect {
		return rr.current.Copy()
	}
	if rr.past != nil && rr.past.PublicKey == *expect {
		return rr.past.Copy()
	}
	if rr.future != nil && rr.future.PublicKey == *expect {
		return rr.future.Copy()
	}
	return nil
}
