package log

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Level is the minimum level that will be emitted.
type Level int32

const (
	LevelError Level = iota
	LevelInfo
	LevelTrace
	LevelDebug
)

var curLevel atomic.Int32

// multi is a simple fan-out writer (stderr + optional syslog).
type multi struct {
	mu sync.Mutex
	ws []io.Writer
}

func (m *multi) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, w := range m.ws {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

var (
	mu         sync.Mutex
	base       = &multi{ws: []io.Writer{os.Stderr}}
	buf        *bufio.Writer
	logger     *log.Logger
	flushTimer *time.Ticker
	insta      bool
)

// Init sets the base writer, level, and instaflush behavior.
func Init(stderr io.Writer, level Level, instaflush bool) {
	mu.Lock()
	defer mu.Unlock()
	if stderr == nil {
		stderr = os.Stderr
	}
	base.ws = []io.Writer{stderr}
	insta = instaflush
	curLevel.Store(int32(level))
	rebuildLocked()
}

// AttachSyslog adds an extra sink (used by tests or by EnableSyslog).
func AttachSyslog(w io.Writer) {
	if w == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	base.ws = append(base.ws, w)
	rebuildLocked()
}

// EnableSyslog connects to the local syslog and attaches it as a sink.
func EnableSyslog(tag string) error {
	sw, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, tag)
	if err != nil {
		return err
	}
	AttachSyslog(sw)
	return nil
}

// SetLevel changes the active level.
func SetLevel(l Level) { curLevel.Store(int32(l)) }

// SetInstaflush toggles line buffering. Switching to instaflush flushes any
// pending buffered data immediately.
func SetInstaflush(v bool) {
	mu.Lock()
	defer mu.Unlock()
	if insta == v {
		return
	}
	insta = v
	if buf != nil && v {
		_ = buf.Flush()
	}
	rebuildLocked()
}

// Flush forces a flush when buffering is enabled.
func Flush() {
	mu.Lock()
	defer mu.Unlock()
	if buf != nil {
		_ = buf.Flush()
	}
}

// ---- printing ------------------------------------------------------------

func Errorf(format string, a ...any) {
	out("[ERROR] "+format, a...)
}

func Infof(format string, a ...any) {
	if Level(curLevel.Load()) >= LevelInfo {
		out("[INFO] "+format, a...)
	}
}

func Tracef(format string, a ...any) {
	if Level(curLevel.Load()) >= LevelTrace {
		out("[TRACE] "+format, a...)
	}
}

func Debugf(format string, a ...any) {
	if Level(curLevel.Load()) >= LevelDebug {
		out("[DEBUG] "+format, a...)
	}
}

func out(format string, a ...any) {
	mu.Lock()
	defer mu.Unlock()
	if logger == nil {
		rebuildLocked()
	}
	logger.Printf(format, a...)
}

// ---- internals -----------------------------------------------------------

func rebuildLocked() {
	// build sink chain
	var w io.Writer = base
	if insta {
		buf = nil
		logger = log.New(w, "", log.Ldate|log.Ltime|log.Lmicroseconds)
		stopFlusherLocked()
		return
	}

	// buffered mode
	buf = bufio.NewWriterSize(w, 16*1024)
	logger = log.New(buf, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	startFlusherLocked()
}

func startFlusherLocked() {
	stopFlusherLocked()
	flushTimer = time.NewTicker(2 * time.Second)
	go func(t *time.Ticker) {
		for range t.C {
			mu.Lock()
			if buf != nil {
				_ = buf.Flush()
			}
			mu.Unlock()
		}
	}(flushTimer)
}

func stopFlusherLocked() {
	if flushTimer != nil {
		flushTimer.Stop()
		flushTimer = nil
	}
}

// Helper for mapping from your config.Verbose, if you want it.
func LevelFromVerbose(verbose int) Level {
	// Common mapping used in main.go:
	//   default -> Error, VerboseInfo -> Info, VerboseTrace -> Trace
	switch verbose {
	case 2:
		return LevelTrace
	case 1:
		return LevelInfo
	default:
		return LevelError
	}
}

// Optional convenience for non-formatted messages.
func Info(a ...any)  { Infof("%s", fmt.Sprint(a...)) }
func Trace(a ...any) { Tracef("%s", fmt.Sprint(a...)) }
func Error(a ...any) { Errorf("%s", fmt.Sprint(a...)) }
