package tls

// --- record & handshake -------------------------------------------------

const (
	tlsContentTypeHandshake uint8 = 22 // TLS record type “Handshake”
	tlsHandshakeClientHello uint8 = 1  // Handshake msg “ClientHello”
)

// --- extensions ---------------------------------------------------------

const (
	tlsExtServerName uint16 = 0 // SNI (Server Name Indication)
)

// --- small error used as sentinel --------------------------------------

type parseErr string

func (e parseErr) Error() string { return string(e) }

// returned by extractSNI when the packet isn’t a ClientHello
var errNotHello = parseErr("not a ClientHello")
