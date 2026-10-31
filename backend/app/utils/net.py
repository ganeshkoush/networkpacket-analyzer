"""Small network helpers shared by analyzers."""
from __future__ import annotations

import ipaddress
from functools import lru_cache

# Conventional port -> service names. These are hints about the *registered use* of a
# port, not evidence about what actually crossed the wire.
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp-server", 68: "dhcp-client", 69: "tftp", 80: "http", 110: "pop3",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmp-trap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1900: "ssdp", 3306: "mysql", 3389: "rdp", 5060: "sip",
    5353: "mdns", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}


def service_hint(port: int) -> str | None:
    """Return the conventional service name for a port, if one is known."""
    return WELL_KNOWN_PORTS.get(port)


@lru_cache(maxsize=65536)
def is_private_ip(ip: str) -> bool:
    """True for private/loopback/link-local addresses; False for public or unparsable."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
