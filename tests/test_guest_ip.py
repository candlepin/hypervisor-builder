"""Unit tests for the guest-IP discovery of the libvirt and hyperv
CLIs, and the first_ipv4 helper they share.

The ssh layer is replaced by a recording fake, so the tests verify the
exact remote commands, the stdin discipline for the guest name and the
address parsing without any network. All addresses are RFC 5737
documentation addresses.
"""

from hypervisor import FailException
from hypervisor.virt import first_ipv4
from hypervisor.virt.hyperv.hypervcli import HypervCLI
from hypervisor.virt.libvirt.libvirtcli import LibvirtCLI

# The exact PowerShell command virtwho-test proved against real
# Hyper-V hosts: the name is read from stdin ([Console]::In) and the
# adapter list is post-filtered by the exact VM name (the adapter's
# own Name is the NIC name, "Network Adapter" by default).
HYPERV_CMD = (
    'PowerShell -Command "$n=[Console]::In.ReadToEnd().Trim(); '
    '(Get-VMNetworkAdapter -VMName $n | Where-Object VMName -eq $n).IpAddresses"'
)

DOMIFADDR_AGENT_OUTPUT = """\
 Name       MAC address        Protocol     Address
 -------------------------------------------------------------------------------
 lo         00:00:00:00:00:00  ipv4         127.0.0.1/8
 eth0       52:54:00:aa:bb:cc  ipv4         192.0.2.50/24
 eth0       52:54:00:aa:bb:cc  ipv6         fe80::5054:ff:feaa:bbcc
"""

DOMIFADDR_ARP_OUTPUT = """\
 Name       MAC address        Protocol     Address
 -------------------------------------------------------------------------------
 vnet0      52:54:00:aa:bb:cc  ipv4         192.0.2.51/24
"""

# What (Get-VMNetworkAdapter ...).IpAddresses prints for a guest with
# one IPv4 and one IPv6 address.
HYPERV_OUTPUT = "{192.0.2.60, fe80::5054:ff:feaa:bbcc}\n"


class FakeSSH:
    """Records runcmd calls and plays back scripted results."""

    def __init__(self, results=()):
        self.results = list(results)
        self.calls = []

    def runcmd(self, cmd, if_stdout=False, timeout=None, input_text=None):
        self.calls.append(
            {
                "cmd": cmd,
                "if_stdout": if_stdout,
                "timeout": timeout,
                "input_text": input_text,
            }
        )
        result = self.results.pop(0) if self.results else (0, "")
        if isinstance(result, Exception):
            raise result
        return result


def make_libvirt(fake):
    cli = LibvirtCLI("192.0.2.10", "user", "pwd")
    cli.ssh = fake
    return cli


def make_hyperv(fake):
    cli = HypervCLI("192.0.2.11", "user", "pwd")
    cli.ssh = fake
    return cli


class TestFirstIpv4:
    def test_first_ipv4_wins_over_loopback(self):
        assert first_ipv4(DOMIFADDR_AGENT_OUTPUT) == "192.0.2.50"

    def test_cidr_prefix_is_dropped(self):
        assert first_ipv4("192.0.2.50/24") == "192.0.2.50"

    def test_ipv6_only_yields_none(self):
        assert first_ipv4("fe80::5054:ff:feaa:bbcc") is None

    def test_no_address_yields_none(self):
        assert first_ipv4("no addresses here") is None


class TestLibvirtGuestIp:
    def test_agent_source_first_with_name_on_stdin(self):
        fake = FakeSSH([(0, DOMIFADDR_AGENT_OUTPUT)])
        ip = make_libvirt(fake).guest_ip("guest-1")
        assert ip == "192.0.2.50"
        assert len(fake.calls) == 1
        call = fake.calls[0]
        assert call["cmd"] == 'read -r dom; virsh domifaddr "$dom" --source agent'
        assert call["input_text"] == "guest-1\n"
        assert call["if_stdout"] is True

    def test_arp_fallback_when_agent_finds_nothing(self):
        fake = FakeSSH([(0, ""), (0, DOMIFADDR_ARP_OUTPUT)])
        ip = make_libvirt(fake).guest_ip("guest-1")
        assert ip == "192.0.2.51"
        assert (
            fake.calls[1]["cmd"] == 'read -r dom; virsh domifaddr "$dom" --source arp'
        )

    def test_arp_fallback_when_agent_errors(self):
        fake = FakeSSH([(1, ""), (0, DOMIFADDR_ARP_OUTPUT)])
        assert make_libvirt(fake).guest_ip("guest-1") == "192.0.2.51"

    def test_none_when_both_sources_fail(self):
        fake = FakeSSH([(1, ""), (1, "")])
        assert make_libvirt(fake).guest_ip("guest-1") is None
        assert [c["cmd"].rsplit(" ", 1)[-1] for c in fake.calls] == ["agent", "arp"]

    def test_timeout_on_agent_falls_back_to_arp(self):
        fake = FakeSSH([FailException("timed out"), (0, DOMIFADDR_ARP_OUTPUT)])
        assert make_libvirt(fake).guest_ip("guest-1") == "192.0.2.51"

    def test_timeout_on_both_sources_yields_none(self):
        fake = FakeSSH([FailException("timed out"), FailException("timed out")])
        assert make_libvirt(fake).guest_ip("guest-1") is None

    def test_query_is_bounded(self):
        fake = FakeSSH([(0, DOMIFADDR_AGENT_OUTPUT)])
        make_libvirt(fake).guest_ip("guest-1")
        assert fake.calls[0]["timeout"] is not None

    def test_guest_name_never_enters_the_command(self):
        hostile = 'guest"; rm -rf / #$(reboot)'
        fake = FakeSSH([(0, DOMIFADDR_AGENT_OUTPUT)])
        make_libvirt(fake).guest_ip(hostile)
        call = fake.calls[0]
        assert hostile not in call["cmd"]
        assert call["input_text"] == f"{hostile}\n"


class TestHypervGuestIp:
    def test_fixed_command_with_name_on_stdin(self):
        fake = FakeSSH([(0, HYPERV_OUTPUT)])
        ip = make_hyperv(fake).guest_ip("guest-1")
        assert ip == "192.0.2.60"
        call = fake.calls[0]
        assert call["cmd"] == HYPERV_CMD
        assert call["input_text"] == "guest-1\n"
        assert call["if_stdout"] is True

    def test_exact_name_post_filter_is_present(self):
        # -VMName treats wildcards as patterns: the command must keep
        # the Where-Object exact-VM-name filter.
        assert "Where-Object VMName -eq $n" in HYPERV_CMD

    def test_ipv6_and_loopback_are_ignored(self):
        fake = FakeSSH([(0, "{fe80::1, 127.0.0.1, 192.0.2.61}\n")])
        assert make_hyperv(fake).guest_ip("guest-1") == "192.0.2.61"

    def test_empty_output_yields_none(self):
        fake = FakeSSH([(0, "")])
        assert make_hyperv(fake).guest_ip("guest-1") is None

    def test_timeout_yields_none(self):
        fake = FakeSSH([FailException("timed out")])
        assert make_hyperv(fake).guest_ip("guest-1") is None

    def test_query_is_bounded(self):
        fake = FakeSSH([(0, HYPERV_OUTPUT)])
        make_hyperv(fake).guest_ip("guest-1")
        assert fake.calls[0]["timeout"] is not None

    def test_guest_name_never_enters_the_command(self):
        hostile = "guest* | Remove-VM"
        fake = FakeSSH([(0, HYPERV_OUTPUT)])
        make_hyperv(fake).guest_ip(hostile)
        call = fake.calls[0]
        assert hostile not in call["cmd"]
        assert call["input_text"] == f"{hostile}\n"
