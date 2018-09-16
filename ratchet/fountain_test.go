package ratchet

import (
	"crypto/rand"
	"testing"
)

func TestFountainMarshal(t *testing.T) {
	nf, err := NewFountain(3600, rand.Reader)
	if err != nil {
		t.Fatalf("NewFountain: %s", err)
	}
	m := nf.Marshall()
	nf2 := new(Fountain).Unmarshall(m)
	if nf2.startdate != nf.startdate {
		t.Error("StartDate")
	}
	if nf2.duration != nf.duration {
		t.Error("Duration")
	}
	if nf2.serviceDesc.ratchet.counter != nf.serviceDesc.ratchet.counter {
		t.Error("Ratchet/counter")
	}
	if nf2.serviceDesc.ratchet.static != nf.serviceDesc.ratchet.static {
		t.Error("Ratchet/static")
	}
	if nf2.serviceDesc.ratchet.dynamic != nf.serviceDesc.ratchet.dynamic {
		t.Error("Ratchet/dynamic")
	}
	if nf2.serviceDesc.ratchet.privateKey != nf.serviceDesc.ratchet.privateKey {
		t.Error("Ratchet/privateKey")
	}
	if nf2.serviceDesc.ratchet.PublicKey != nf.serviceDesc.ratchet.PublicKey {
		t.Error("Ratchet/PublicKey")
	}
}
