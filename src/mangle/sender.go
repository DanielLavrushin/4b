package mangle

var (
	SendRaw     = func([]byte) error { return nil }
	SendDelayed = func([]byte, uint) error { return nil }
)

func SetRawSendFunc(f func([]byte) error)           { SendRaw = f }
func SetDelayedSendFunc(f func([]byte, uint) error) { SendDelayed = f }
