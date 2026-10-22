package sandbox

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// controlDispatcher serves supervisor→worker control frames on stdin and
// writes responses to stdout.
type controlDispatcher struct {
	mu       sync.Mutex
	session  *agent.Session
	stdout   io.Writer
	requests map[FrameType]func(context.Context, Frame) (Frame, error)
}

func newControlDispatcher(session *agent.Session, stdout io.Writer) *controlDispatcher {
	d := &controlDispatcher{
		session:  session,
		stdout:   stdout,
		requests: make(map[FrameType]func(context.Context, Frame) (Frame, error)),
	}
	if session.Supplement != nil {
		d.requests[FrameSupplementRequest] = func(ctx context.Context, frame Frame) (Frame, error) {
			if err := session.Supplement(ctx, frame.Text); err != nil {
				return Frame{Type: FrameError, Error: err.Error()}, nil
			}
			return Frame{Type: FrameSupplementReadyResponse, Bool: true}, nil
		}
	}
	if session.SupplementReady != nil {
		d.requests[FrameSupplementReadyQuery] = func(_ context.Context, _ Frame) (Frame, error) {
			return Frame{Type: FrameSupplementReadyResponse, Bool: session.SupplementReady()}, nil
		}
	}
	if session.ToolActivity != nil {
		d.requests[FrameToolActivityQuery] = func(_ context.Context, _ Frame) (Frame, error) {
			count, idle := session.ToolActivity()
			return Frame{Type: FrameToolActivityResponse, Int32: count, DurationS: int64(idle.Seconds())}, nil
		}
	}
	if session.InterruptBackgroundTools != nil {
		d.requests[FrameInterruptBackground] = func(_ context.Context, _ Frame) (Frame, error) {
			return Frame{Type: FrameInterruptResult, Bool: session.InterruptBackgroundTools()}, nil
		}
	}
	if session.TerminalObserved != nil {
		d.requests[FrameTerminalObservedQuery] = func(_ context.Context, _ Frame) (Frame, error) {
			return Frame{Type: FrameTerminalObservedResponse, Bool: session.TerminalObserved()}, nil
		}
	}
	return d
}

func (d *controlDispatcher) serve(ctx context.Context, stdin io.Reader) {
	if len(d.requests) == 0 {
		return
	}
	reader := bufio.NewReaderSize(stdin, 64<<10)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		frame, err := ReadFrame(reader)
		if err != nil {
			return
		}
		handler, ok := d.requests[frame.Type]
		if !ok {
			continue
		}
		response, err := handler(ctx, frame)
		if err != nil {
			_ = d.write(Frame{Type: FrameError, Error: err.Error()})
			continue
		}
		if response.Type != "" {
			_ = d.write(response)
		}
	}
}

func (d *controlDispatcher) write(frame Frame) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return WriteFrame(d.stdout, frame)
}

// streamWorkerSession forwards transcript/result frames and serves control
// requests on stdin until the run finishes.
func streamWorkerSession(ctx context.Context, stdin io.Reader, stdout io.Writer, session *agent.Session) error {
	dispatcher := newControlDispatcher(session, stdout)
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go dispatcher.serve(serveCtx, stdin)

	messages := session.Messages
	for {
		select {
		case message, ok := <-messages:
			if !ok {
				messages = nil
				continue
			}
			if err := dispatcher.write(Frame{Type: FrameMessage, Message: &message}); err != nil {
				return err
			}
		case result, ok := <-session.Result:
			if !ok {
				return WriteFrame(stdout, Frame{Type: FrameError, Error: "the backend closed its result channel"})
			}
			return WriteFrame(stdout, Frame{Type: FrameResult, Result: &result})
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// supervisorControl forwards one control request to the worker and waits for
// the matching response frame type on the shared stdout reader.
func supervisorControl(
	ctx context.Context,
	stdin io.Writer,
	readResponse func(context.Context, FrameType) (Frame, error),
	request Frame,
	expect FrameType,
) (Frame, error) {
	if err := WriteFrame(stdin, request); err != nil {
		return Frame{}, err
	}
	for {
		frame, err := readResponse(ctx, expect)
		if err != nil {
			return Frame{}, err
		}
		if frame.Type == FrameError {
			return frame, errors.New(frame.Error)
		}
		if frame.Type == expect {
			return frame, nil
		}
	}
}
