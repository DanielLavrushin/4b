package mangle

var SendRaw func(pkt []byte) error = func(_ []byte) error { return nil }

var SendDelayed func(pkt []byte, delayMs uint) error = func(_ []byte, _ uint) error { return nil }
