import os
import importlib.util
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


HELPER = str(Path(__file__).with_name("test-process-reaper.py"))


@unittest.skipUnless(sys.platform == "linux", "Linux adopting-parent helper")
class TestProcessReaper(unittest.TestCase):
    def command(self, code, *args, timeout=5):
        return [sys.executable, HELPER, "--timeout", str(timeout), "--", sys.executable, "-c", code, *map(str, args)]

    def test_final_echild_outranks_delayed_parent_observation(self):
        spec = importlib.util.spec_from_file_location("test_process_reaper", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with mock.patch.object(helper.sys, "argv", [HELPER, "--", "synthetic"]), \
             mock.patch.object(helper.ctypes, "CDLL") as library, \
             mock.patch.object(helper.os, "fork", return_value=12345), \
             mock.patch.object(helper.os, "pidfd_open", return_value=42), \
             mock.patch.object(helper.os, "close"), \
             mock.patch.object(helper.signal, "pidfd_send_signal"), \
             mock.patch.object(helper.signal, "signal"), \
             mock.patch.object(helper.os, "waitpid", side_effect=[(12345, 0), ChildProcessError]), \
             mock.patch.object(helper.time, "monotonic", side_effect=[0, 0, 0, 2]), \
             mock.patch.object(helper, "stop_owned") as stop:
            library.return_value.prctl.return_value = 0
            self.assertEqual(helper.main(), 0)
            stop.assert_not_called()

    def test_reaps_orphan_while_command_still_checks_pid_absence(self):
        code = """
import os, time
read, write = os.pipe()
middle = os.fork()
if middle == 0:
    pid = os.fork()
    if pid == 0:
        time.sleep(.05)
        os._exit(0)
    os.write(write, str(pid).encode())
    os._exit(0)
os.close(write)
pid = int(os.read(read, 64))
os.close(read)
os.waitpid(middle, 0)
deadline = time.monotonic() + 3
while os.path.exists('/proc/%d' % pid) and time.monotonic() < deadline:
    time.sleep(.005)
assert not os.path.exists('/proc/%d' % pid), 'orphan PID was not reaped'
"""
        result = subprocess.run(self.command(code), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("adopted_reaped=1 final=ECHILD cleanup_after_test=none", result.stderr)

    def test_live_leak_fails_and_leaves_foreign_process_untouched(self):
        foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "orphan"
                code = """
import os, sys, time
pid = os.fork()
if pid == 0:
    os.setsid()
    time.sleep(60)
    os._exit(0)
open(sys.argv[1], 'w').write(str(pid))
"""
                result = subprocess.run(self.command(code, path), capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertIn("final=ECHILD cleanup_after_test=surviving_descendant", result.stderr)
                self.assertFalse(Path("/proc", path.read_text()).exists())
                self.assertIsNone(foreign.poll(), "helper signalled an unrelated process")
        finally:
            foreign.terminate()
            foreign.wait(timeout=5)

    def test_interruption_cleans_owned_parent_and_detached_child(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pids"
            code = """
import os, sys, time
pid = os.fork()
if pid == 0:
    os.setsid()
    time.sleep(60)
    os._exit(0)
open(sys.argv[1], 'w').write('%d %d' % (os.getpid(), pid))
time.sleep(60)
"""
            command = subprocess.Popen(self.command(code, path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 3
                while not path.exists() and time.monotonic() < deadline:
                    time.sleep(.005)
                self.assertTrue(path.exists(), "fixture never launched its owned tree")
                command.send_signal(signal.SIGTERM)
                _, errors = command.communicate(timeout=8)
                self.assertEqual(command.returncode, 143, errors)
                self.assertIn("final=ECHILD cleanup_after_test=signal:15", errors)
                for pid in path.read_text().split():
                    self.assertFalse(Path("/proc", pid).exists(), f"owned PID {pid} remains")
            finally:
                if command.poll() is None:
                    command.send_signal(signal.SIGTERM)
                    command.communicate(timeout=8)

    def test_timeout_and_command_failure_are_never_success(self):
        result = subprocess.run(self.command("import time; time.sleep(60)", timeout=.05), capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("final=ECHILD cleanup_after_test=command_timeout", result.stderr)
        result = subprocess.run(self.command("raise SystemExit(7)"), capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("final=ECHILD cleanup_after_test=none", result.stderr)


if __name__ == "__main__":
    unittest.main()
