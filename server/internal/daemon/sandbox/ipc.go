package sandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// FrameType identifies one IPC frame.
type FrameType string

const (
	FrameMessage FrameType = "message"
	FrameResult  FrameType = "result"
	FrameError   FrameType = "error"

	// Supervisor → worker control frames (bidirectional Session IPC).
	FrameSupplementRequest       FrameType = "supplement_request"
	FrameSupplementReadyQuery    FrameType = "supplement_ready_query"
	FrameSupplementReadyResponse FrameType = "supplement_ready"
	FrameToolActivityQuery       FrameType = "tool_activity_query"
	FrameToolActivityResponse    FrameType = "tool_activity"
	FrameInterruptBackground     FrameType = "interrupt_background"
	FrameInterruptResult         FrameType = "interrupt_result"
	FrameTerminalObservedQuery   FrameType = "terminal_observed_query"
	FrameTerminalObservedResponse FrameType = "terminal_observed"
)

// Frame is one supervisor/worker IPC record.
//
// The worker speaks first only in response to the manifest; after that every
// frame is one of a transcript message, the final result, or an error. There
// is no request/response channel in V1: a run-scoped supplement needs a
// bidirectional transport, and a sandboxed attempt starts without one.
type Frame struct {
	Type    FrameType      `json:"type"`
	Message *agent.Message `json:"message,omitempty"`
	Result  *agent.Result  `json:"result,omitempty"`
	Error   string         `json:"error,omitempty"`
	// Control payloads for bidirectional Session IPC.
	Text      string `json:"text,omitempty"`
	Bool      bool   `json:"bool,omitempty"`
	Int32     int32  `json:"int32,omitempty"`
	DurationS int64  `json:"duration_s,omitempty"`
}

// WriteFrame writes one JSON frame followed by a newline.
func WriteFrame(w io.Writer, frame Frame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("sandbox: encode the frame: %w", err)
	}
	if len(encoded) > maxFrameBytes {
		return errors.New("sandbox: the frame is too large")
	}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("sandbox: write the frame: %w", err)
	}
	return nil
}

// ReadFrame reads one JSON frame.
//
// A line that is not a complete frame is an error rather than a partially
// decoded message: a truncated transcript must not be reported as if the
// worker had said it.
func ReadFrame(r *bufio.Reader) (Frame, error) {
	line, err := readLimitedLine(r)
	if err != nil {
		return Frame{}, err
	}
	var frame Frame
	if err := json.Unmarshal([]byte(line), &frame); err != nil {
		return Frame{}, fmt.Errorf("sandbox: decode the frame: %w", err)
	}
	switch frame.Type {
	case FrameMessage:
		if frame.Message == nil {
			return Frame{}, errors.New("sandbox: a message frame carries no message")
		}
	case FrameResult:
		if frame.Result == nil {
			return Frame{}, errors.New("sandbox: a result frame carries no result")
		}
	case FrameError:
		if strings.TrimSpace(frame.Error) == "" {
			return Frame{}, errors.New("sandbox: an error frame carries no error")
		}
	case FrameSupplementRequest:
		if strings.TrimSpace(frame.Text) == "" {
			return Frame{}, errors.New("sandbox: supplement_request requires text")
		}
	case FrameSupplementReadyQuery, FrameToolActivityQuery, FrameTerminalObservedQuery, FrameInterruptBackground:
		// empty payload
	case FrameSupplementReadyResponse, FrameTerminalObservedResponse, FrameInterruptResult:
		// bool payload
	case FrameToolActivityResponse:
		if frame.Int32 < 0 {
			return Frame{}, errors.New("sandbox: tool_activity count is invalid")
		}
	default:
		return Frame{}, fmt.Errorf("sandbox: unknown frame type %q", frame.Type)
	}
	return frame, nil
}

func seconds(value int64) time.Duration {
	if value <= 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}
