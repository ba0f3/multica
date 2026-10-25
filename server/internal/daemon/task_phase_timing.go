package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/multica-ai/multica/server/pkg/agent"
)

type taskPhase string

const (
	taskPhaseClaimed             taskPhase = "claimed"
	taskPhasePrepareStarted      taskPhase = "prepare_started"
	taskPhaseRepoCacheStarted    taskPhase = "repo_cache_started"
	taskPhaseRepoCacheReady      taskPhase = "repo_cache_ready"
	taskPhaseRuntimeResolved     taskPhase = "runtime_resolved"
	taskPhaseSkillsReady         taskPhase = "skills_ready"
	taskPhaseEnvironmentReady    taskPhase = "environment_ready"
	taskPhaseRuntimeStarted      taskPhase = "runtime_started"
	taskPhaseFirstOutputReceived taskPhase = "first_output_received"
	taskPhaseFirstToolUse        taskPhase = "first_tool_use"
	taskPhaseTurnCompleted       taskPhase = "turn_completed"
	taskPhaseFinished            taskPhase = "finished"
)

type taskPhaseSample struct {
	Phase        taskPhase
	PhaseElapsed time.Duration
	TotalElapsed time.Duration
}

// taskPhaseRecorder records daemon-local task lifecycle timing. It is
// diagnostic-only: Mark has no error path and callers must not use it to make
// task-state decisions.
type taskPhaseRecorder struct {
	logger *slog.Logger
	now    func() time.Time

	mu       sync.Mutex
	started  time.Time
	previous time.Time
	marked   map[taskPhase]struct{}
}

func newTaskPhaseRecorder(logger *slog.Logger, now func() time.Time) *taskPhaseRecorder {
	if now == nil {
		now = time.Now
	}
	started := now()
	return &taskPhaseRecorder{
		logger:   logger,
		now:      now,
		started:  started,
		previous: started,
		marked:   make(map[taskPhase]struct{}),
	}
}

// Mark records and logs a phase only once. PhaseElapsed is the time since the
// previous recorded phase, not the duration of the named phase itself; skipped
// phases therefore widen the next recorded interval. A duplicate mark returns
// a zero sample and does not consume the injected clock.
func (r *taskPhaseRecorder) Mark(phase taskPhase) taskPhaseSample {
	if r == nil {
		return taskPhaseSample{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.marked[phase]; ok {
		return taskPhaseSample{}
	}

	now := r.now()
	sample := taskPhaseSample{
		Phase:        phase,
		PhaseElapsed: now.Sub(r.previous),
		TotalElapsed: now.Sub(r.started),
	}
	r.marked[phase] = struct{}{}
	r.previous = now
	if r.logger != nil {
		r.logger.Info("task phase recorded",
			"task_phase", phase,
			"phase_elapsed_ms", sample.PhaseElapsed.Milliseconds(),
			"total_elapsed_ms", sample.TotalElapsed.Milliseconds(),
		)
	}
	return sample
}

type taskPhaseRecorderContextKey struct{}

func withTaskPhaseRecorder(ctx context.Context, recorder *taskPhaseRecorder) context.Context {
	return context.WithValue(ctx, taskPhaseRecorderContextKey{}, recorder)
}

func taskPhaseRecorderFromContext(ctx context.Context) *taskPhaseRecorder {
	recorder, _ := ctx.Value(taskPhaseRecorderContextKey{}).(*taskPhaseRecorder)
	return recorder
}

func isTaskOutputReceived(msg agent.Message) bool {
	switch msg.Type {
	case agent.MessageText, agent.MessageThinking:
		return msg.Content != ""
	case agent.MessageToolUse, agent.MessageToolResult, agent.MessageError:
		return true
	default:
		return false
	}
}

func isTaskToolUse(msg agent.Message) bool {
	return msg.Type == agent.MessageToolUse
}

// attemptTiming uses independent anchors: intervening diagnostic phases cannot
// change the meaning of a metric, and every timestamp retains its monotonic part.
type attemptTiming struct {
	mu     sync.Mutex
	logger *slog.Logger
	now    func() time.Time
	points map[string]time.Time
}

func newAttemptTiming(logger *slog.Logger, task, attempt, provider, backend string, now func() time.Time) *attemptTiming {
	if now == nil {
		now = time.Now
	}
	if logger != nil {
		logger = logger.With("task_id", task, "attempt_id", attempt, "provider", provider, "backend", backend)
	}
	return &attemptTiming{logger: logger, now: now, points: map[string]time.Time{"started": now()}}
}
func (t *attemptTiming) Mark(point string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.points[point]; ok {
		return
	}
	now := t.now()
	t.points[point] = now
	for _, metric := range []struct{ name, start, end string }{
		{"repo_prepare_ms", "repo_started", "repo_ready"}, {"runtime_resolve_ms", "runtime_started", "runtime_ready"}, {"environment_prepare_ms", "environment_started", "environment_ready"}, {"sandbox_launch_ms", "sandbox_spawn", "worker_ready"}, {"cli_start_ms", "worker_ready", "cli_started"}, {"first_output_ms", "cli_started", "first_output"}, {"turn_total_ms", "started", "finished"},
	} {
		if metric.end != point {
			continue
		}
		start, ok := t.points[metric.start]
		if ok && t.logger != nil {
			t.logger.Info("task attempt timing", metric.name, now.Sub(start).Milliseconds())
		}
	}
}

type attemptTimingContextKey struct{}

func attemptTimingFromContext(ctx context.Context) *attemptTiming {
	value, _ := ctx.Value(attemptTimingContextKey{}).(*attemptTiming)
	return value
}
