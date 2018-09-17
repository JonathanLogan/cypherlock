// Package timesource contains types to test time-dependent code. It does inefficient time subscriber managament.
package timesource

import (
	"sync"
	"time"
)

// TimeChannel receives time events through a channel.
type TimeChannel chan time.Time

// MockClock implements a commmon time source for testing.
type MockClock struct {
	currentTime time.Time
	mutex       *sync.Mutex
	subscribers []TimeChannel
}

// NewMockClock returns a new MockClock with
func NewMockClock(now time.Time) *MockClock {
	return &MockClock{
		mutex:       new(sync.Mutex),
		currentTime: now,
		subscribers: make([]TimeChannel, 0, 10),
	}
}

// Subscribe to a Mockclock. Important: MUST unsubscribe.
func (cl *MockClock) Subscribe(c TimeChannel) {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	cl.subscribers = append(cl.subscribers, c)
}

// Unsubscribe from a Mockclock.
func (cl *MockClock) Unsubscribe(c TimeChannel) {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	for i, s := range cl.subscribers {
		if s == c {
			cl.subscribers[i] = nil
		}
	}
}

// SetTime sets the Mockclock's time and broadcasts it to all subscribers.
func (cl *MockClock) SetTime(t time.Time) {
	cl.mutex.Lock()
	cl.currentTime = t
	cl.mutex.Unlock()
	cl.broadcast()
}

// broadcast the current time.
func (cl *MockClock) broadcast() {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	for _, s := range cl.subscribers {
		if s != nil {
			q := s
			t := cl.currentTime
			go func() {
				defer func() {
					recover()
				}()
				q <- t
			}()
		}
	}
}

// Advance the Clock by d, in half-second increments.
func (cl *MockClock) Advance(d time.Duration) {
	steps := d / (time.Second / 2)
	remain := d - (steps * (time.Second / 2))
	for i := time.Duration(0); i < steps; i++ {
		cl.mutex.Lock()
		cl.currentTime = cl.currentTime.Add(time.Second / 2)
		cl.mutex.Unlock()
		cl.broadcast()
	}
	cl.mutex.Lock()
	cl.currentTime = cl.currentTime.Add(remain)
	cl.mutex.Unlock()
	cl.broadcast()
}

// Now returns the current time of the Mockclock.
func (cl *MockClock) Now() time.Time {
	cl.mutex.Lock()
	defer cl.mutex.Unlock()
	return cl.currentTime
}

// MockTicker implements a mock ticker.
type MockTicker struct {
	clock    *MockClock
	duration time.Duration
	fireTime time.Time
	c        chan time.Time // Incoming
	co       chan time.Time // Outgoing
}

// NewTicker returns a new ticker for the clock.
func (cl *MockClock) NewTicker(d time.Duration) Ticker {
	mt := &MockTicker{
		clock:    cl,
		duration: d,
		fireTime: cl.Now().Add(d),
		c:        make(chan time.Time, 1),
		co:       make(chan time.Time, 1),
	}
	cl.Subscribe(mt.c)
	go func() {
		for t := range mt.c {
			if t.After(mt.fireTime) || t.Equal(mt.fireTime) {
				mt.co <- t
				mt.fireTime = mt.clock.Now().Add(mt.duration)
			}
		}
	}()
	return mt
}

// Stop the ticker.
func (mt *MockTicker) Stop() {
	mt.clock.Unsubscribe(mt.c)
	close(mt.co)
	close(mt.c)
}

// Chan returns channel of ticker.
func (mt *MockTicker) Chan() <-chan time.Time {
	return mt.co
}
