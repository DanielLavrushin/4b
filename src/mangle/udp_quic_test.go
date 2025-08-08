package mangle

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/google/gopacket/layers"
)

func mkInitialHeader() []byte {
	// minimal 7 bytes: long header bit set, version bytes, dcid len=0, pad 1
	return []byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
}

func TestUDPFilter_QuicAll_AcceptsInitial(t *testing.T) {
	origIs := quicIsInitial
	quicIsInitial = func(_ []byte) bool { return true }
	t.Cleanup(func() { quicIsInitial = origIs })

	sec := &config.Section{
		UDPFilterQuic: config.UDPFilterQuicAll,
		DPortFilter:   false,
	}
	udp := &layers.UDP{DstPort: 443}
	payload := mkInitialHeader()

	if !udpFiltered(sec, udp, payload) {
		t.Fatalf("UDPFilterQuicAll should accept Initial")
	}
}

func TestUDPFilter_QuicParsed_ParseMode_Match(t *testing.T) {
	origIs := quicIsInitial
	origDec := quicDecryptInitial
	origAsm := quicAssembleCrypto
	origTLS := tlsExtractSNI
	quicIsInitial = func(_ []byte) bool { return true }
	quicDecryptInitial = func(_ []byte, _ []byte) ([]byte, bool) { return []byte("plain"), true }
	quicAssembleCrypto = func(_ []byte) ([]byte, bool) { return []byte("...example.com..."), true }
	tlsExtractSNI = func(_ []byte) ([]byte, error) { return []byte("example.com"), nil }
	t.Cleanup(func() {
		quicIsInitial = origIs
		quicDecryptInitial = origDec
		quicAssembleCrypto = origAsm
		tlsExtractSNI = origTLS
	})

	sec := &config.Section{
		UDPFilterQuic: config.UDPFilterQuicParsed,
		SNIDetection:  0, // parse
		SNIDomains:    []string{"example.com"},
		DPortFilter:   false,
	}
	udp := &layers.UDP{DstPort: 443}
	payload := mkInitialHeader()

	if !udpFiltered(sec, udp, payload) {
		t.Fatalf("parsed parse-mode should match example.com")
	}
}

func TestUDPFilter_QuicParsed_Brute_AllDomains(t *testing.T) {
	origIs := quicIsInitial
	origDec := quicDecryptInitial
	origAsm := quicAssembleCrypto
	quicIsInitial = func(_ []byte) bool { return true }
	quicDecryptInitial = func(_ []byte, _ []byte) ([]byte, bool) { return []byte("plain"), true }
	quicAssembleCrypto = func(_ []byte) ([]byte, bool) { return []byte("anything"), true }
	t.Cleanup(func() {
		quicIsInitial = origIs
		quicDecryptInitial = origDec
		quicAssembleCrypto = origAsm
	})

	sec := &config.Section{
		UDPFilterQuic: config.UDPFilterQuicParsed,
		SNIDetection:  1, // brute
		AllDomains:    1,
		DPortFilter:   false,
	}
	udp := &layers.UDP{DstPort: 443}
	payload := mkInitialHeader()

	if !udpFiltered(sec, udp, payload) {
		t.Fatalf("parsed brute AllDomains should accept")
	}
}
