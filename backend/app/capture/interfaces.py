"""Enumerate capture interfaces and classify them (Wi-Fi / Ethernet / VPN / loopback / other).

Classification is best-effort and read-only: sysfs on Linux, `networksetup -listallhardwareports`
(fixed arguments) on macOS, adapter descriptions on Windows, then name heuristics.
"""
from __future__ import annotations

import logging
import re
import subprocess
import sys
from pathlib import Path

from app.models.live import InterfaceInfo, InterfaceKind

logger = logging.getLogger(__name__)

_VPN = re.compile(r"^(utun|tun|tap|ppp|wg|ipsec|gpd|zt|tailscale|nordlynx)|vpn|wireguard|tunnel|openvpn|anyconnect|tailscale", re.I)
_WIFI = re.compile(r"wi-?fi|wireless|wlan|802\.11", re.I)
_ETH = re.compile(r"ethernet|^eth\d|^enp|^eno|^ens|gigabit|\blan\b", re.I)
_VIRTUAL_PREFIXES = ("awdl", "llw", "anpi", "gif", "stf", "ap", "bridge", "docker", "veth", "br-", "virbr", "vmnet", "vboxnet")


def _macos_hardware_ports() -> dict[str, str]:
    """Map BSD device name -> hardware port label (e.g. en0 -> Wi-Fi)."""
    try:
        out = subprocess.run(["networksetup", "-listallhardwareports"], capture_output=True, text=True,
                             timeout=3, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    ports: dict[str, str] = {}
    label = None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            label = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and label:
            ports[line.split(":", 1)[1].strip()] = label
    return ports


def classify(name: str, description: str = "", flags: str = "", hw_ports: dict[str, str] | None = None) -> InterfaceKind:
    text = f"{name} {description}"
    if "LOOPBACK" in flags.upper() or name == "lo" or name.startswith("lo") and name[2:].isdigit() \
            or re.search(r"loopback", text, re.I):
        return "loopback"
    if sys.platform.startswith("linux"):
        base = Path("/sys/class/net") / name
        try:
            if (base / "wireless").exists() or (base / "phy80211").exists():
                return "wifi"
            if (base / "tun_flags").exists():
                return "vpn"
        except OSError:
            pass
    label = (hw_ports or {}).get(name, "")
    if label:
        if _WIFI.search(label):
            return "wifi"
        if _VPN.search(label):
            return "vpn"
        if re.search(r"ethernet|lan|thunderbolt|usb", label, re.I):
            return "ethernet"
    if _VPN.search(text):
        return "vpn"
    if _WIFI.search(text):
        return "wifi"
    if _ETH.search(text):
        return "ethernet"
    return "other"


def list_interfaces() -> list[InterfaceInfo]:
    """Interfaces Scapy can see. Does not open any of them or require privileges."""
    from scapy.interfaces import ifaces  # imported lazily: Scapy init is slow

    hw_ports = _macos_hardware_ports() if sys.platform == "darwin" else {}
    result: list[InterfaceInfo] = []
    try:
        devices = list(ifaces.values())
    except Exception:
        logger.exception("Could not enumerate interfaces")
        return []
    for dev in devices:
        name = str(getattr(dev, "name", "") or "")
        if not name:
            continue
        desc = str(getattr(dev, "description", "") or name)
        flags = str(getattr(dev, "flags", "") or "")
        addrs: list[str] = []
        for ips in (getattr(dev, "ips", None) or {}).values():
            addrs.extend(str(a) for a in ips)
        up = None if not flags else ("UP" in flags.split("+") or "DRV_RUNNING" in flags)
        result.append(InterfaceInfo(name=name, description=desc, kind=classify(name, desc, flags, hw_ports),
                                    addresses=addrs[:6], is_up=up))
    order = {"wifi": 0, "ethernet": 1, "vpn": 2, "loopback": 3, "other": 4}
    # Interfaces with addresses first within a kind: they are the ones users want.
    result.sort(key=lambda i: (order[i.kind], not i.addresses, i.name))
    return result
