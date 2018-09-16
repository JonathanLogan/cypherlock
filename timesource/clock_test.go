package timesource

import (
	"testing"
	"time"
)

func TestR(t *testing.T) {
	ct := time.Now()
	nc := NewMockClock(ct)
	Clock = nc
	ti := Clock.NewTicker(time.Second)
	nc.Advance(time.Second)
	<-ti.Chan()
}
