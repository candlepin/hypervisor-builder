"""Unit tests for hypervisor.ssh.SSHConnect.

The paramiko SSHClient is replaced by a recording fake, so these
tests verify the connection pooling, the per-command timeout, the
dead-transport reconnect and the stdin input channel without any
network.
"""

import socket
import threading

import paramiko
import pytest

from hypervisor import FailException
from hypervisor.ssh import SSHConnect

# Timers started by FakeChannel to simulate slow commands; cancelled
# after each test so no thread outlives the session.
_channel_timers = []


@pytest.fixture(autouse=True)
def _cancel_channel_timers():
    yield
    for timer in _channel_timers:
        timer.cancel()
    _channel_timers.clear()


class FakeTransport:
    def __init__(self, active=True):
        self.active = active

    def is_active(self):
        return self.active


class FakeChannel:
    """Models the real paramiko channel closely enough that the
    runcmd timeout paths fire the way they do against real paramiko:
    recv_exit_status() blocks on status_event (it never raises), and
    the event is only set when the command's exit status arrives.
    """

    def __init__(self, exit_status=0, exit_delay=None):
        self.status_event = threading.Event()
        self.exit_status = exit_status
        self.timeout = None
        self.shutdown_write_called = False
        if exit_delay is None:
            # The command finished before runcmd looked at it.
            self.status_event.set()
        else:
            # The command's exit status arrives only after a delay
            # (a slow or hung remote command).
            timer = threading.Timer(exit_delay, self.status_event.set)
            timer.daemon = True
            timer.start()
            _channel_timers.append(timer)

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv_exit_status(self):
        # Real paramiko: an unbounded event wait, never a raise.
        self.status_event.wait()
        return self.exit_status

    def shutdown_write(self):
        self.shutdown_write_called = True


class FakeStdin:
    def __init__(self, channel, write_raises=None):
        self.channel = channel
        self.write_raises = write_raises
        self.written = []

    def write(self, data):
        if self.write_raises is not None:
            raise self.write_raises
        self.written.append(data)

    def flush(self):
        pass


class FakePipe:
    """The stdout or stderr file object of an executed command."""

    def __init__(self, channel, data=b"", read_raises=None):
        self.channel = channel
        self.data = data
        self.read_raises = read_raises

    def read(self):
        # A read-phase timeout on a real channel surfaces as a
        # socket.timeout raised from recv (hence read).
        if self.read_raises is not None:
            raise self.read_raises
        return self.data


@pytest.fixture
def fake_clients(monkeypatch):
    """Replace paramiko.SSHClient with a recording fake.

    Each constructed client consumes the next plan (an empty plan
    means: exit 0, empty stdout/stderr). Plans describe what the
    client's exec_command channel does.
    """
    default_plan = {
        "stdout": b"",
        "stderr": b"",
        "exit_status": 0,
        "exit_delay": None,
        "exec_raises": None,
        "write_raises": None,
        "read_raises": None,
        "transport_active": True,
    }

    class FakeSSHClient:
        plans = []
        instances = []

        def __init__(self):
            cls = type(self)
            cls.instances.append(self)
            plan = dict(default_plan)
            if cls.plans:
                plan.update(cls.plans.pop(0))
            self.plan = plan
            self.commands = []
            self.exec_timeouts = []
            self.closed = False
            self.transport = FakeTransport(active=plan["transport_active"])
            self.channel = FakeChannel(
                exit_status=plan["exit_status"], exit_delay=plan["exit_delay"]
            )
            self.stdin = FakeStdin(self.channel, write_raises=plan["write_raises"])
            self.stdout = FakePipe(self.channel, data=plan["stdout"])
            self.stderr = FakePipe(
                self.channel, data=plan["stderr"], read_raises=plan["read_raises"]
            )

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, *args, **kwargs):
            pass

        def get_transport(self):
            return self.transport

        def exec_command(self, cmd, timeout=None):
            if self.plan["exec_raises"] is not None:
                raise self.plan["exec_raises"]
            self.commands.append(cmd)
            self.exec_timeouts.append(timeout)
            return self.stdin, self.stdout, self.stderr

        def close(self):
            self.closed = True

    monkeypatch.setattr(paramiko, "SSHClient", FakeSSHClient)
    return FakeSSHClient


def make_ssh():
    return SSHConnect("192.0.2.10", "user", pwd="secret")


class TestPooling:
    def test_consecutive_commands_reuse_one_connection(self, fake_clients):
        ssh = make_ssh()
        ssh.runcmd("echo one")
        ssh.runcmd("echo two")
        assert len(fake_clients.instances) == 1
        assert fake_clients.instances[0].commands == ["echo one", "echo two"]

    def test_inactive_transport_is_not_reused(self, fake_clients):
        ssh = make_ssh()
        ssh.runcmd("echo one")
        fake_clients.instances[0].transport.active = False
        ssh.runcmd("echo two")
        assert len(fake_clients.instances) == 2
        # The dead connection never saw the second command, and was
        # closed rather than left to linger.
        assert fake_clients.instances[0].commands == ["echo one"]
        assert fake_clients.instances[0].closed
        assert fake_clients.instances[1].commands == ["echo two"]

    def test_close_releases_the_pooled_connection(self, fake_clients):
        ssh = make_ssh()
        ssh.runcmd("echo one")
        client = fake_clients.instances[0]
        ssh.close()
        assert client.closed
        assert ssh._ssh is None
        # The next command opens a fresh connection.
        ssh.runcmd("echo two")
        assert len(fake_clients.instances) == 2

    def test_context_manager_closes_the_connection(self, fake_clients):
        # The one-shot pattern (with SSHConnect(...) as ssh) must not
        # leak a live session per call.
        ssh = make_ssh()
        with ssh:
            ssh.runcmd("echo one")
        assert fake_clients.instances[0].closed
        assert ssh._ssh is None


class TestReconnect:
    def test_exec_failure_reconnects_and_reruns(self, fake_clients):
        # A transport-class failure before the command started (drop,
        # channel-open timeout): the command never ran, so it is safe
        # to reconnect once and start it again.
        fake_clients.plans.append({"exec_raises": paramiko.SSHException("drop")})
        ssh = make_ssh()
        code, output = ssh.runcmd("echo one")
        assert (code, output) == (0, "")
        assert len(fake_clients.instances) == 2
        assert fake_clients.instances[1].commands == ["echo one"]
        # The dead connection was closed, not just dropped.
        assert fake_clients.instances[0].closed

    def test_stdin_write_failure_propagates_without_rerun(self, fake_clients):
        # The command already started: re-running it could execute a
        # non-idempotent command twice, so the failure must propagate.
        fake_clients.plans.append({"write_raises": EOFError("channel gone")})
        ssh = make_ssh()
        with pytest.raises(EOFError):
            ssh.runcmd("remove-vm x", input_text="data\n")
        # The command ran exactly once and was never re-executed.
        assert len(fake_clients.instances) == 1
        assert fake_clients.instances[0].commands == ["remove-vm x"]
        # The dead connection is dropped so the next call reconnects.
        assert fake_clients.instances[0].closed
        assert ssh._ssh is None
        ssh.runcmd("echo two")
        assert len(fake_clients.instances) == 2


class TestTimeout:
    def test_hung_command_times_out_and_closes_connection(self, fake_clients):
        # The exit status arrives only after 2s. Real paramiko's
        # recv_exit_status() would block on the status event until
        # then (and forever, for a command that never exits); the
        # runcmd timeout must give up without waiting for it.
        fake_clients.plans.append({"exit_delay": 2.0})
        ssh = make_ssh()
        with pytest.raises(FailException):
            ssh.runcmd("sleep 1000", timeout=0.1)
        assert fake_clients.instances[0].closed
        assert ssh._ssh is None

    def test_read_stall_times_out_and_closes_connection(self, fake_clients):
        # The exit status arrived, but reading the output stalls: a
        # real channel raises socket.timeout from read() (a distinct
        # class from TimeoutError on Python < 3.10, as in runcmd).
        fake_clients.plans.append({"read_raises": socket.timeout()})  # noqa: UP041
        ssh = make_ssh()
        with pytest.raises(FailException):
            ssh.runcmd("sleep 1000", timeout=5)
        assert fake_clients.instances[0].closed
        assert ssh._ssh is None

    def test_slow_command_within_timeout_still_succeeds(self, fake_clients):
        fake_clients.plans.append({"exit_delay": 0.1, "stdout": b"done\n"})
        ssh = make_ssh()
        assert ssh.runcmd("slow query", timeout=30) == (0, "done\n")

    def test_timeout_is_applied_to_the_channel(self, fake_clients):
        ssh = make_ssh()
        ssh.runcmd("echo one", timeout=7)
        assert fake_clients.instances[0].channel.timeout == 7

    def test_timeout_bounds_the_channel_open_too(self, fake_clients):
        # paramiko waits up to 3600s for a channel to open on an
        # active-but-broken transport: the per-command timeout must
        # bound that window as well.
        ssh = make_ssh()
        ssh.runcmd("echo one", timeout=7)
        assert fake_clients.instances[0].exec_timeouts == [7]

    def test_no_channel_open_timeout_by_default(self, fake_clients):
        ssh = make_ssh()
        ssh.runcmd("echo one")
        assert fake_clients.instances[0].exec_timeouts == [None]

    def test_no_timeout_by_default(self, fake_clients):
        ssh = make_ssh()
        ssh.runcmd("echo one")
        assert fake_clients.instances[0].channel.timeout is None


class TestInput:
    def test_input_text_rides_stdin(self, fake_clients):
        ssh = make_ssh()
        ssh.runcmd("cat", input_text="guest-1\n")
        client = fake_clients.instances[0]
        assert client.stdin.written == ["guest-1\n"]
        assert client.channel.shutdown_write_called

    def test_write_side_closed_without_input(self, fake_clients):
        ssh = make_ssh()
        ssh.runcmd("echo one")
        client = fake_clients.instances[0]
        assert client.stdin.written == []
        # EOF for remote readers even when nothing is written.
        assert client.channel.shutdown_write_called


class TestBackwardCompatibility:
    def test_runcmd_returns_code_and_stdout(self, fake_clients):
        fake_clients.plans.append({"stdout": b"the output\n"})
        ssh = make_ssh()
        assert ssh.runcmd("echo one") == (0, "the output\n")

    def test_runcmd_positional_if_stdout(self, fake_clients):
        fake_clients.plans.append({"stdout": b"out", "stderr": b"err"})
        ssh = make_ssh()
        assert ssh.runcmd("echo one", True) == (0, "out")

    def test_runcmd_returns_stderr_by_default(self, fake_clients):
        fake_clients.plans.append({"stdout": b"out", "stderr": b"err"})
        ssh = make_ssh()
        assert ssh.runcmd("echo one") == (0, "err")

    def test_runcmd_reports_exit_status(self, fake_clients):
        fake_clients.plans.append({"exit_status": 1, "stderr": b"failed"})
        ssh = make_ssh()
        assert ssh.runcmd("false") == (1, "failed")

    def test_remove_file_uses_the_transfer_path(self, fake_clients, monkeypatch):
        class FakeSftp:
            def __init__(self):
                self.removed = []

            def remove(self, path):
                self.removed.append(path)

        class FakeConn:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        sftp, conn = FakeSftp(), FakeConn()
        ssh = make_ssh()
        monkeypatch.setattr(ssh, "_transfer", lambda: (sftp, conn))
        ssh.remove_file("/remote/file")
        assert sftp.removed == ["/remote/file"]
        assert conn.closed
