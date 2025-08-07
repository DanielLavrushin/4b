package config

import _ "embed"

//go:embed fake_sni.bin
var FakeSNI []byte

//go:embed fake_sni_old.bin
var FakeSNIold []byte

const FakeSNIMaxLen = 1500
