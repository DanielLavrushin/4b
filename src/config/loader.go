package config

var defaultFake = FakeSNIold


func (s *Section) ensureFakePayload() {
    if len(s.FakeSNIPkt) == 0 {        
        s.FakeSNIPkt = make([]byte, len(defaultFake))
        copy(s.FakeSNIPkt, defaultFake)
    }
}