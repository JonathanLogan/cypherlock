package ratchet

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/JonathanLogan/cypherlock/timesource"
)

// SecretFunc is a function that returns a secret for a ratchet key.
type SecretFunc func(expectedPubKey, peerPubKey *[32]byte) (*[32]byte, error)

// Overwriteable for testing.
var unixNow = func() int64 {
	return timesource.Clock.Now().Unix()
}

var (
	// ErrInvalidDuration signifies that a given duration was invalid, that is smaller than 1.
	ErrInvalidDuration = errors.New("ratchet: invalid duration")
	// ErrNoService signifies that attempting to send to a close service will fail.
	ErrNoService = errors.New("ratchet: ratchet fountain service stopped")
	// ErrRatchetNotFound signifies that a secret was requested that refers to a ratchet state that is not current.
	ErrRatchetNotFound = errors.New("ratchet: ratchet not found")
)

// Fountain is a ratchet with timing information, that is: When did a ratchet start, and how often
// does it update.
type Fountain struct {
	startdate   int64    // Unix time of the start date.
	duration    int64    // Number of seconds between ratchet steps.
	serviceDesc *service // Service description.
}

// service description
type service struct {
	c       chan interface{}
	ratchet *RatchetState // The fountain's ratchet.
}

// getRatchet message type, return ratchetstate.
type getRatchet struct {
	c chan *RatchetState
}

// getSecret message type, return calculated secret.
type getSecret struct {
	expect *[32]byte      // Expected pubkey of ratchet
	in     *[32]byte      // Pubkey of peer.
	c      chan *[32]byte // channel on which to return the secret.
}

// stopService message type, return ratchetstate.
type stopService struct {
	c    chan *RatchetState
	stop bool
}

// NewFountain returns a new Fountain for ratchets, it creates a new
// underlying ratchet, sets the start date to now, and sets the duration.
// Returns nil on error. Service MUST be started.
func NewFountain(duration int64, rand io.Reader) (*Fountain, error) {
	if duration < 1 {
		return nil, ErrInvalidDuration
	}
	r, err := NewRatchet(rand)
	if err != nil {
		return nil, err
	}
	return newFountain(r, unixNow(), duration), nil
}

func newFountain(r *RatchetState, startdate, duration int64) *Fountain {
	f := &Fountain{
		startdate: startdate,
		duration:  duration,
		serviceDesc: &service{
			ratchet: r,
		},
	}
	return f
}

// Start the ratcheting service.s
func (f *Fountain) StartService() {
	f.serviceDesc.c = make(chan interface{}, 2)
	go f.service()
}

// Calculate the counter that should be current NOW.
func (f *Fountain) getCurrentStep() uint64 {
	return uint64(((unixNow() - f.startdate) / f.duration) + 1)
}

// Calculate when to do the next step.
func (f *Fountain) getTimeToNextStep() int64 {
	now := unixNow()
	steps := (now - f.startdate) / f.duration      // total steps taken.
	nextStepLifeTime := (steps + 1) * f.duration   // Time after f.startDate the next step takes place
	nextStepTime := f.startdate + nextStepLifeTime // Absolute time
	timeDif := nextStepTime - now                  // How many seconds are missing to next step.
	return timeDif
}

func (f *Fountain) service() {
	first := true
	ring := NewRatchetRing(f.serviceDesc.ratchet, f.getCurrentStep())
	ticker := timesource.Clock.NewTicker((time.Duration(f.getTimeToNextStep()) * time.Second) + time.Millisecond*10) // We add some skew just in case the ticker is early.
MessageLoop:
	for {
		select {
		case <-ticker.Chan(): // Fires when update shall take place.
			newStep := f.getCurrentStep()
			if ring.CurrentStep() < newStep {
				ring.StepTo(newStep)
				r := ring.Current()
				f.serviceDesc.ratchet = r
			}
			if first {
				ticker.Stop()
				ticker = timesource.Clock.NewTicker(time.Duration(f.duration) * time.Second)
			}
		case m := <-f.serviceDesc.c: // Calls to service.
			switch n := m.(type) {
			case getRatchet:
				d := ring.Current()
				n.c <- d
			case getSecret:
				r := ring.Find(n.expect)
				if r == nil {
					n.c <- nil
				} else {
					d := r.SharedSecret(n.in)
					n.c <- d
				}
			case stopService:
				d := ring.Current()
				n.c <- d
				break MessageLoop
			default:
				panic("github.com/JonathanLogan/cypherlock/ratchet: Unknown service message type.")
			}
		}
	}
	close(f.serviceDesc.c)
	f.serviceDesc.c = nil
}

func (f *Fountain) sendToService(d interface{}) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = ErrNoService
			return
		}
	}()
	if f.serviceDesc == nil {
		return ErrNoService
	}
	if f.serviceDesc.c == nil {
		return ErrNoService
	}
	f.serviceDesc.c <- d
	return nil
}

func (f *Fountain) Stop() *RatchetState {
	m := stopService{
		c: make(chan *RatchetState, 1),
	}
	err := f.sendToService(m)
	if err != nil {
		return f.serviceDesc.ratchet
	}
	r := <-m.c
	close(m.c)
	return r
}

func (f *Fountain) getRatchet() *RatchetState {
	m := getRatchet{
		c: make(chan *RatchetState, 1),
	}
	err := f.sendToService(m)
	if err != nil {
		close(m.c)
		return f.serviceDesc.ratchet
	}
	r := <-m.c
	close(m.c)
	return r
}

func (f *Fountain) GetSecret(expectedPubKey, peerPubKey *[32]byte) (*[32]byte, error) {
	inT, pubT := new([32]byte), new([32]byte)
	copy(inT[:], peerPubKey[:])      // Prevent programming errors.
	copy(pubT[:], expectedPubKey[:]) // Prevent programming errors.
	m := getSecret{
		expect: pubT,
		in:     inT,
		c:      make(chan *[32]byte, 1),
	}
	err := f.sendToService(m)
	if err != nil {
		return nil, err
	}
	r := <-m.c
	close(m.c)
	if r == nil {
		return nil, ErrRatchetNotFound
	}
	return r, nil
}

// Marshall a fountain into a byte slice. It does NOT stop the service.
func (f *Fountain) Marshall() []byte {
	o := make([]byte, 16, 136+16)
	binary.BigEndian.PutUint64(o, uint64(f.startdate))
	binary.BigEndian.PutUint64(o[8:], uint64(f.duration))
	r := f.getRatchet()
	d := r.Marshall()
	o = append(o, d...)
	return o
}

// Unmarshall a fountain from  byte slice, returns nil on error.
// Service MUST be started.
func (f *Fountain) Unmarshall(d []byte) *Fountain {
	if len(d) < 136+16 {
		return nil
	}
	startdate := binary.BigEndian.Uint64(d[:8])
	duration := binary.BigEndian.Uint64(d[8:16])
	r := new(RatchetState).Unmarshall(d[16:])
	if r == nil {
		return nil
	}
	return newFountain(r, int64(startdate), int64(duration))
}
