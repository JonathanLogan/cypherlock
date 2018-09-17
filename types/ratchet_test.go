package types

import (
	"testing"
)

func TestPregenerateEntry(t *testing.T) {
	first := NewPregenerateEntry(nil, 1, 10, 100, [32]byte{0x00, 0x01, 0x02})
	second := NewPregenerateEntry(&first.LineHash, 2, 10, 100, [32]byte{0x03, 0x04, 0x05})
	firstM := first.Marshall()
	secondM := second.Marshall()
	firstT := Unmarshall(firstM)
	secondT := Unmarshall(secondM)

	if firstT == nil || secondT == nil {
		t.Fatal("Unmarshall error")
	}
	if firstT.Counter != 1 {
		t.Error("Counter value")
	}
	if firstT.PublicKey != [32]byte{0x00, 0x01, 0x02} {
		t.Error("PublicKey value")
	}
	if firstT.ValidFrom != 10 {
		t.Error("ValidFrom value")
	}
	if firstT.ValidTo != 100 {
		t.Error("ValidTo value")
	}

	if first.Counter != firstT.Counter {
		t.Error("Counter")
	}
	if first.LineHash != firstT.LineHash {
		t.Error("LineHash")
	}
	if first.ValidFrom != firstT.ValidFrom {
		t.Error("ValidFrom")
	}
	if first.ValidTo != firstT.ValidTo {
		t.Error("ValidTo")
	}
	if first.PublicKey != firstT.PublicKey {
		t.Error("PublicKey")
	}
	if second.Counter != secondT.Counter {
		t.Error("Counter")
	}
	if second.LineHash != secondT.LineHash {
		t.Error("LineHash")
	}
	if second.ValidFrom != secondT.ValidFrom {
		t.Error("ValidFrom")
	}
	if second.ValidTo != secondT.ValidTo {
		t.Error("ValidTo")
	}
	if second.PublicKey != secondT.PublicKey {
		t.Error("PublicKey")
	}
	if !firstT.Validate(nil) {
		t.Error("First no validate")
	}
	if !secondT.Validate(&firstT.LineHash) {
		t.Error("Second no validate")
	}
}
