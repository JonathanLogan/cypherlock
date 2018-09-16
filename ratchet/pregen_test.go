package ratchet

import (
	"github.com/JonathanLogan/cypherlock/timesource"
	"crypto/rand"
	"testing"
	"time"
)

var nc *timesource.MockClock

func init() {
	nc = timesource.NewMockClock(time.Unix(0, 0))
	timesource.Clock = nc
}

func TestPregenerator(t *testing.T) {
	nf, err := NewFountain(3600, rand.Reader)
	if err != nil {
		t.Fatalf("NewFountain: %s", err)
	}
	pg := NewPregeneratorFromFountain(nf, 3*3600)
	nf.StartService()
	rat1 := nf.getRatchet()
	r := pg.Generate()
	nc.Advance(time.Second * time.Duration(3600*2))
	rat2 := nf.getRatchet()

	if rat1.privateKey == rat2.privateKey {
		t.Fatal("Fountain ratchet not advanced")
	}
	if rat1.counter != 1 || rat2.counter != 2 {
		t.Fatal("False advancement")
	}
	r2 := pg.Generate()
	_, _ = r2, r
}

func TestPregeneratorMarshal(t *testing.T) {
	nf, err := NewFountain(3600, rand.Reader)
	if err != nil {
		t.Fatalf("NewFountain: %s", err)
	}
	pg := NewPregeneratorFromFountain(nf, 1000)
	// modify away from default values
	pg.lastCounter = 12093
	pg.lastLineHash[3] = 0xff
	m := pg.Marshall()
	pg2 := new(PreGenerator).Unmarshall(nf, m)
	if pg.startdate != pg2.startdate {
		t.Error("startdate")
	}
	if pg.duration != pg2.duration {
		t.Error("duration")
	}
	if pg.pregenInterval != pg2.pregenInterval {
		t.Error("pregenInterval")
	}
	if pg.lastCounter != pg2.lastCounter {
		t.Error("lastCounter")
	}
	if pg.lastLineHash != pg2.lastLineHash {
		t.Error("lastLineHash")
	}
	if pg2.ratchet.counter != pg.ratchet.counter {
		t.Error("Ratchet/counter")
	}
	if pg2.ratchet.static != pg.ratchet.static {
		t.Error("Ratchet/static")
	}
	if pg2.ratchet.dynamic != pg.ratchet.dynamic {
		t.Error("Ratchet/dynamic")
	}
	if pg2.ratchet.privateKey != pg.ratchet.privateKey {
		t.Error("Ratchet/privateKey")
	}
	if pg2.ratchet.PublicKey != pg.ratchet.PublicKey {
		t.Error("Ratchet/PublicKey")
	}

}
