"""'Hide localhost / private IP destinations / local network domains' (Settings → Domains).

Applied to the Web Activity table and the dashboard's domain lists. Hiding only removes rows from those views; the analysis,
connections, findings and the network map still contain the traffic.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from app.models.app_settings import DomainSettings

_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".intranet", ".corp", ".private")


def _ips(values: Iterable[str]) -> list:
    out = []
    for v in values:
        try:
            out.append(ipaddress.ip_address(v))
        except ValueError:
            continue
    return out


def is_hidden(domain: str, resolved_ips: Iterable[str], s: DomainSettings) -> bool:
    name = domain.lower().rstrip(".")
    ips = _ips(resolved_ips)
    if s.hide_localhost and (name == "localhost" or name.endswith(".localhost") or (ips and all(i.is_loopback for i in ips))):
        return True
    if s.hide_private_ips and ips and all(i.is_private or i.is_link_local for i in ips):
        return True
    if s.hide_local_domains and ("." not in name or name.endswith(_LOCAL_SUFFIXES)):
        return True
    return False
