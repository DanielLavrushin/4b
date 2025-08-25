package mangle

import "time"

func init() {
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			tcpStreamGC(5*time.Minute, 256*1024) // 5 минут или 256KB на поток
		}
	}()
}
