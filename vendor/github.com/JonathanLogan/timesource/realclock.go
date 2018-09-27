package timesource

import "time"

// TimeTicker overloads time.Ticker for augmentation.
type TimeTicker time.Ticker

// Chan returns the channel to which the ticker sends. Should be used exclusively instead of time.Ticker.C
func (tt *TimeTicker) Chan() <-chan time.Time {
	return tt.C
}

// Stop the ticker.
func (tt *TimeTicker) Stop() {
	(*time.Ticker)(tt).Stop()
}

// RealClock implements the Clock interface for the actual go+system clock.
type RealClock struct{}

// Now returns the current time.
func (rc RealClock) Now() time.Time {
	return time.Now()
}

// NewTicker returns a new Ticker.
func (rc RealClock) NewTicker(d time.Duration) Ticker {
	t := time.NewTicker(d)
	return (*TimeTicker)(t)
}
