package tls

type Verdict struct {
	SNIPtr       []byte // raw slice inside the packet
	SNILen       int
	Target       bool   // true if domain ∈ target  && ∉ exclude
	TargetSNIPtr []byte // where the “interesting” suffix starts
	TargetSNILen int
}
