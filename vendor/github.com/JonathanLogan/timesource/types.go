package timesource

import "time"

// Clock is our default clock, which is the Real clock. Overwrite with MockClock in tests.
var Clock ClockSource = RealClock{}

// Ticker interface.
type Ticker interface {
	Stop()
	Chan() <-chan time.Time
}

// ClockSource is the interface that MockClock and RealClock implement.
type ClockSource interface {
	Now() time.Time // Return the current time.
	NewTicker(d time.Duration) Ticker
}
