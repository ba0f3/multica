#!/usr/bin/env python3
"""Run a synthetic Linux test command with an adopting, reaping parent."""

import argparse
import ctypes
import math
import os
import signal
import sys
import time


def parent_of(pid):
    with open(f"/proc/{pid}/stat") as state:
        raw = state.read(16385)
    if len(raw) > 16384:
        raise RuntimeError("oversized process state")
    return int(raw.rsplit(")", 1)[1].split()[1])


def stop_owned(owner, deadline):
    scanned = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if time.monotonic() >= deadline:
                return
            if not entry.name.isdecimal():
                continue
            scanned += 1
            if scanned > 65536:
                raise RuntimeError("test cleanup process limit exceeded")
            pid = int(entry.name)
            try:
                if parent_of(pid) != owner:
                    continue
                fd = os.pidfd_open(pid)
                try:
                    # Revalidate after acquiring a stable handle. Never signal
                    # an unrelated PID or a numerical process group.
                    if parent_of(pid) == owner:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                finally:
                    os.close(fd)
            except (FileNotFoundError, ProcessLookupError):
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 3600:
        parser.error("provide a command and a timeout in (0, 3600]")
    if sys.platform != "linux":
        parser.error("this test helper requires Linux")

    # This setting applies only to this helper process. It does not alter PID1,
    # the host, the test's process isolation or any browser sandbox.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "test subreaper unavailable")
    probe = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(probe, 0)
    finally:
        os.close(probe)

    interrupted = None

    def interrupt(number, _frame):
        nonlocal interrupted
        interrupted = number

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    owner = os.getpid()
    child = os.fork()
    if child == 0:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        try:
            os.execvpe(command[0], command, os.environ)
        except OSError as error:
            print(f"test command could not start: {error}", file=sys.stderr)
            os._exit(127)

    command_deadline = time.monotonic() + args.timeout
    status, ended, cleanup_deadline = None, None, None
    reason = None
    adopted = 0
    confirmed = False
    try:
        while True:
            # The kernel's empty-child observation outranks a scheduling pause.
            # Do not infer a surviving descendant from elapsed time alone.
            try:
                pid, code = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                confirmed = True
                break
            now = time.monotonic()
            if interrupted is not None:
                reason = f"signal:{interrupted}"
            elif reason is None and ended is None and now >= command_deadline:
                reason = "command_timeout"
            elif reason is None and ended is not None and now - ended >= 1:
                reason = "surviving_descendant"
            if reason is not None:
                if cleanup_deadline is None:
                    cleanup_deadline = now + 5
                if now >= cleanup_deadline:
                    raise RuntimeError("test descendant cleanup unconfirmed")
                stop_owned(owner, cleanup_deadline)
            if pid:
                if pid == child:
                    status = os.waitstatus_to_exitcode(code)
                    ended = time.monotonic()
                else:
                    adopted += 1
                continue
            time.sleep(0.002)
    except BaseException:
        if reason is None:
            reason = "helper_error"
        raise
    finally:
        # Unexpected Python errors must not silently orphan the owned command.
        # The same bounded, stable-handle cleanup applies to interruption/errors.
        if not confirmed:
            deadline = cleanup_deadline or time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    stop_owned(owner, deadline)
                    pid, code = os.waitpid(-1, os.WNOHANG)
                    if pid == child:
                        status = os.waitstatus_to_exitcode(code)
                    elif pid:
                        adopted += 1
                except ChildProcessError:
                    confirmed = True
                    break
                except (OSError, RuntimeError):
                    pass
                time.sleep(0.002)
        print(
            f"test subreaper: adopted_reaped={adopted} "
            f"final={'ECHILD' if confirmed else 'UNCONFIRMED'} "
            f"cleanup_after_test={reason or ('none' if confirmed else 'error')}",
            file=sys.stderr,
        )
    if not confirmed or status is None:
        return 125
    if interrupted is not None:
        return 128 + interrupted
    if reason is not None:
        return 124 if reason == "command_timeout" else 125
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    sys.exit(main())
