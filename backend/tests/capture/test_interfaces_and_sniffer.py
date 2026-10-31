import errno
import os

import pytest

from app.capture import ScapySource, list_interfaces
from app.capture.interfaces import classify
from app.capture.sniffer import CaptureStartError, classify_open_error
from scapy.error import Scapy_Exception


@pytest.mark.parametrize("name, desc, flags, hw, kind", [
    ("lo0", "lo0", "UP+LOOPBACK", {}, "loopback"),
    ("lo", "lo", "", {}, "loopback"),
    ("Loopback Pseudo-Interface 1", "Software Loopback Interface 1", "", {}, "loopback"),
    ("en0", "en0", "", {"en0": "Wi-Fi"}, "wifi"),
    ("en5", "en5", "", {"en5": "USB 10/100/1000 LAN"}, "ethernet"),
    ("utun3", "utun3", "", {}, "vpn"),
    ("tun0", "tun0", "", {}, "vpn"),
    ("Ethernet 2", "Realtek PCIe GbE Family Controller", "", {}, "ethernet"),
    ("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", "", {}, "wifi"),
    ("Local Area Connection", "TAP-Windows Adapter V9 (OpenVPN)", "", {}, "vpn"),
    ("awdl0", "awdl0", "", {}, "other"),
])
def test_classify(name, desc, flags, hw, kind):
    assert classify(name, desc, flags, hw) == kind


def test_list_interfaces_needs_no_privileges_and_has_loopback():
    ifaces = list_interfaces()
    assert ifaces and all(i.name and i.kind for i in ifaces)
    assert any(i.kind == "loopback" for i in ifaces)


@pytest.mark.parametrize("exc, code, permission", [
    (PermissionError(errno.EACCES, "denied"), "permission_denied", True),
    (OSError(errno.EPERM, "Operation not permitted"), "permission_denied", True),
    (Scapy_Exception("Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root ! (sudo)"),
     "permission_denied", True),
    (RuntimeError("Npcap not installed"), "capture_driver_missing", False),
    (OSError(errno.ENODEV, "No such device"), "interface_unavailable", False),
    (ValueError("weird"), "capture_failed", False),
])
def test_classify_open_error(exc, code, permission):
    err = classify_open_error(exc)
    assert err.code == code and err.permission is permission and err.message
    if permission:
        assert err.hint


def test_real_open_without_privileges_fails_gracefully_or_succeeds():
    """On a dev machine without root this exercises the genuine OS permission error path."""
    loop = next(i.name for i in list_interfaces() if i.kind == "loopback")
    src = ScapySource()
    try:
        src.start(loop, lambda p: None)
    except CaptureStartError as exc:
        assert exc.code in {"permission_denied", "capture_driver_missing", "interface_unavailable", "capture_failed"}
        assert exc.message
    else:
        src.stop()  # privileged environment: capture opened; make sure stop is clean
        src.stop()


def test_scapy_source_drives_real_sniffer_machinery(monkeypatch, tmp_path):
    """Replace only the privileged socket with a pcap reader; AsyncSniffer/callback/stop are real."""
    import threading

    import pcap_factory as pf
    from scapy.config import conf
    from scapy.utils import PcapReader

    path = pf.write_pcap(tmp_path / "x.pcap", [pf.tcp("1.1.1.1", "10.0.0.2", 1000 + i, 80, ts=pf.T0 + i) for i in range(5)])
    opened = {}

    def fake_l2listen(iface=None, promisc=None, **kw):
        opened.update(iface=iface, promisc=promisc)
        return PcapReader(str(path))

    monkeypatch.setattr(conf, "L2listen", fake_l2listen)
    got, done = [], threading.Event()

    def cb(pkt):
        got.append(pkt)
        if len(got) == 5:
            done.set()

    src = ScapySource()
    src.start("lo", cb)
    assert done.wait(5)
    src.stop()
    src.stop()
    assert opened == {"iface": "lo", "promisc": False}  # non-promiscuous by default
    assert src.failure() is None
