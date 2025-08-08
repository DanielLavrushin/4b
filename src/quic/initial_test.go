package quic

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexEq(t *testing.T, got []byte, wantHex string) {
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("\n got:  %s\n want: %s", hex.EncodeToString(got), wantHex)
	}
}

func TestV1DerivationVectors(t *testing.T) {
	dcid := mustHex("8394c8f03e515708")

	// HKDF-Extract(saltV1, dcid)
	prk := hkdfExtractSHA256(saltV1, dcid)
	hexEq(t, prk, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44") // RFC 9001 A.1

	// client_in → client secret
	client, err := hkdfExpandLabel(prk, "client in", 32)
	if err != nil {
		t.Fatal(err)
	}
	hexEq(t, client, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")

	// keys/iv/hp for v1
	key, err := hkdfExpandLabel(client, "quic key", 16)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := hkdfExpandLabel(client, "quic iv", 12)
	if err != nil {
		t.Fatal(err)
	}
	hp, err := hkdfExpandLabel(client, "quic hp", 16)
	if err != nil {
		t.Fatal(err)
	}

	hexEq(t, key, "1f369613dd76d5467730efcbe3b1a22d")
	hexEq(t, iv, "fa044b2f42a3fd3b46fb255c")
	hexEq(t, hp, "9f50449e04a0e810283a1e9933adedd2")
}

func TestV2IsInitialMapping(t *testing.T) {
	// Minimal long header: |1|long|type|..|, version=v2, DCID/SCID lens = 0
	b := make([]byte, 7)
	b[0] = 0x80 | (0x01 << 4) // long header + type=01 (Initial in v2)
	binary.BigEndian.PutUint32(b[1:5], versionV2)
	// dcid_len=0, scid_len=0
	// b[5]=0, b[6]=0 (already zero)

	if !IsInitial(b) {
		t.Fatalf("v2 Initial mapping failed (expected true)")
	}
	// Retry in v2 is 00 → not Initial
	b[0] = 0x80 | (0x00 << 4)
	if IsInitial(b) {
		t.Fatalf("v2 Retry misclassified as Initial")
	}
}
