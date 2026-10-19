//go:build linux || darwin

package agent

import (
	"strings"
	"testing"
)

func TestCursorTerminationConfirmsAfterSignal(t *testing.T) {
	active, elapsed := true, false
	signals, observations := 0, 0
	err := terminateCursorOwnedGroup(123, func() (bool, error) {
		observations++
		// A process-table observation can consume the remaining budget. Its
		// pre-signal answer cannot establish that the signalled group survived.
		elapsed = true
		return active, nil
	}, func() error {
		signals++
		active = false
		return nil
	}, func() bool { return elapsed }, func() { t.Fatal("unexpected retry") })
	if err != nil || signals != 1 || observations == 0 {
		t.Fatalf("confirmed cleanup: error=%v signals=%d observations=%d", err, signals, observations)
	}
}

func TestCursorTerminationKeepsDeadlineForSurvivingGroup(t *testing.T) {
	signals := 0
	err := terminateCursorOwnedGroup(123, func() (bool, error) { return true, nil }, func() error {
		signals++
		return nil
	}, func() bool { return true }, func() { t.Fatal("retry beyond deadline") })
	if err == nil || !strings.Contains(err.Error(), "still active after 1s") || signals != 1 {
		t.Fatalf("unconfirmed cleanup: error=%v signals=%d", err, signals)
	}
}
