package clientinterface

import "testing"

func TestParseFilename(t *testing.T) {
	validFrom, validTo, _ := parseFilename("39812-44791.oracle")
	if validFrom != 39812 {
		t.Error("ValidFrom")
	}
	if validTo != 44791 {
		t.Error("ValidTo")
	}
}
