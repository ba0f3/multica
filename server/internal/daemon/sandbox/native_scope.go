package sandbox

import (
	"os"
	"regexp"
	"sync"
)

type NativeLimits struct {
	MemoryBytes int64
	PIDsLimit   int64
	NanoCPUs    int64
}

// NativeScope only receives daemon-owned paths and limits. Controller access
// remains outside the worker; neither its socket nor cgroupfs is mounted there.
type NativeScope struct {
	RunPath     string
	ControlPath string
	BwrapPath   string
	CgroupRoot  string
	Limits      NativeLimits

	mu       sync.Mutex
	cached   bool
	cacheKey string
	watch    []nativeWatch
}

var nativeUnitName = regexp.MustCompile(`^multica-[A-Za-z0-9_.-]{1,180}\.scope$`)
var nativeProfileKey = regexp.MustCompile(`^[a-f0-9]{64}$`)

type NativeProfileLease struct {
	file *os.File
	once sync.Once
	err  error
}

func (l *NativeProfileLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() { l.err = l.file.Close() })
	return l.err
}
