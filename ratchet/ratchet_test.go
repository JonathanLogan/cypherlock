package ratchet

import (
	"crypto/rand"
	"testing"
)

func TestState(t *testing.T) {
	r, err := NewRatchet(rand.Reader)
	if err != nil {
		t.Fatalf("Reader: %s", err)
	}
	rx, err := NewRatchet(rand.Reader)
	if err != nil {
		t.Fatalf("Reader2: %s", err)
	}
	if r.counter != 1 || rx.counter != 1 {
		t.Fatal("NewRatchet: counter")
	}
	if r.static == rx.static {
		t.Fatal("static not random")
	}
	if r.dynamic == rx.dynamic {
		t.Fatal("dynamic not random")
	}
	if r.privateKey == rx.privateKey {
		t.Fatal("Private key matches")
	}
	if r.PublicKey == rx.PublicKey {
		t.Fatal("Public key matches")
	}

	m := r.Marshall()
	r2 := new(State).Unmarshall(m)
	if r2 == nil {
		t.Fatal("Unmarshall")
	}
	if r.counter != r2.counter {
		t.Error("counter mismatch")
	}
	if r.static != r2.static {
		t.Error("static mismatch")
	}
	if r.dynamic != r2.dynamic {
		t.Error("dynamic mismatch")
	}
	if r.privateKey != r2.privateKey {
		t.Error("privateKey mismatch")
	}
	if r.PublicKey != r2.PublicKey {
		t.Error("PublicKey mismatch")
	}
	r.Step()
	if r.counter == r2.counter {
		t.Error("counter not advanced")
	}
	if r.dynamic == r2.dynamic {
		t.Error("dynamic not advanced")
	}
	if r.static != r2.static {
		t.Error("static changed")
	}
	if r.privateKey == r2.privateKey {
		t.Error("Private key unchanged")
	}
	if r.PublicKey == r2.PublicKey {
		t.Error("Public key unchanged")
	}
	if r.privateKey == r2.dynamic {
		t.Error("Private key bleed dynamic")
	}
	if r.privateKey == r2.static {
		t.Error("Private key bleed static")
	}
	if r.dynamic == r2.static {
		t.Error("dynamic bleed from static")
	}
}

func TestCopy(t *testing.T) {
	r, _ := NewRatchet(rand.Reader)
	r2 := r.Copy()
	if r.counter != r2.counter {
		t.Error("counter")
	}
	if r.dynamic != r2.dynamic {
		t.Error("dynamic")
	}
	if r.static != r2.static {
		t.Error("static")
	}
	if r.privateKey != r2.privateKey {
		t.Error("privateKey")
	}
	if r.PublicKey != r2.PublicKey {
		t.Error("PublicKey")
	}
	if &r == &r2 {
		t.Error("Struct address")
	}
	if &r.counter == &r2.counter {
		t.Error("counter address")
	}
	if &r.static == &r2.static {
		t.Error("static address")
	}
	if &r.dynamic == &r2.dynamic {
		t.Error("Dynamic address")
	}
	if &r.privateKey == &r2.privateKey {
		t.Error("privateKey address")
	}
	if &r.PublicKey == &r2.PublicKey {
		t.Error("PublicKey address")
	}
}
