import re


def first_ipv4(text):
    """Return the first IPv4 address in the text, loopback excluded.

    Guest-IP discovery output (virsh domifaddr, Get-VMNetworkAdapter)
    lists the addresses the management plane knows in its own order,
    which may put the guest's loopback or IPv6 addresses first; the
    address callers need is the first real IPv4. domifaddr reports
    addresses with a CIDR prefix, which the pattern ignores.
    """
    for address in re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", text):
        if not address.startswith("127."):
            return address
    return None
