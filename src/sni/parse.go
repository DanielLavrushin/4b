package sni

type SniInfo struct {
	SNI   string
	SrcIP string
	DstIP string
	Proto string
}

func ParseSNI(payload []byte) (string, bool) {
	// Parse the SNI from the TLS Client Hello payload
	return "", false
}
