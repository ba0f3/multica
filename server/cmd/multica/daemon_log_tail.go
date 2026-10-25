package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

func tailLogFile(logPath string, lines int, follow bool) error {
	ctx, stop := notifyShutdownContext(context.Background())
	defer stop()
	return streamDaemonLog(ctx, logPath, lines, follow, os.Stdout, 500*time.Millisecond)
}

// streamDaemonLog follows the file by name so rotation and truncation survive
// daemon restarts without depending on the system's tail implementation.
func streamDaemonLog(ctx context.Context, path string, lines int, follow bool, output io.Writer, interval time.Duration) error {
	if lines < 0 {
		return fmt.Errorf("--lines must be non-negative")
	}
	f, err := openLogForTail(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	start, err := logTailStart(f, info.Size(), lines)
	if err != nil {
		return err
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	n, err := io.Copy(output, f)
	if err != nil || !follow {
		return err
	}
	offset := start + n
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		current, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue // Rotation may leave the path absent until the next write.
		}
		if err != nil {
			return err
		}
		if !os.SameFile(info, current) {
			next, err := openLogForTail(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			_ = f.Close()
			f = next
			info, err = f.Stat()
			if err != nil {
				return err
			}
			offset = 0
		} else if current.Size() < offset {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			offset = 0
		}
		n, err := io.Copy(output, f)
		if err != nil {
			return err
		}
		offset += n
	}
}

// logTailStart scans backwards in bounded chunks, preserving an unterminated
// final line and avoiding loading a large daemon log into memory.
func logTailStart(f *os.File, size int64, lines int) (int64, error) {
	if lines == 0 {
		return size, nil
	}
	buf := make([]byte, 8192)
	for pos := size; pos > 0; {
		chunk := min(int64(len(buf)), pos)
		pos -= chunk
		n, err := f.ReadAt(buf[:chunk], pos)
		if err != nil && err != io.EOF {
			return 0, err
		}
		for i := n - 1; i >= 0; i-- {
			if buf[i] == '\n' && pos+int64(i) != size-1 {
				lines--
				if lines == 0 {
					return pos + int64(i) + 1, nil
				}
			}
		}
	}
	return 0, nil
}
