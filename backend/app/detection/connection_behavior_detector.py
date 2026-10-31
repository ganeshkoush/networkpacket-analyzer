"""Unusual connection behaviour: large asymmetric uploads and cleartext protocols."""
from __future__ import annotations

from app.detection.base_detector import BaseDetector
from app.detection.models import Finding, FindingType
from app.detection.severity import ramp
from app.models.analysis import AnalysisResult, Connection
from app.utils.net import WELL_KNOWN_PORTS, is_private_ip


def _mb(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MiB"


class ConnectionBehaviorDetector(BaseDetector):
    """Inspects the reported connections (the largest flows by bytes).

    * **Unusual outbound transfer** - a private client sent far more than it received to a
      public server (volume and asymmetry thresholds), more suspicious on a port with no
      well-known service.
    * **Cleartext protocol** - an established Telnet/FTP/POP3/IMAP/rlogin session
      (credentials and data cross the network unencrypted).
    """

    name = "connection_behavior"

    def detect(self, result: AnalysisResult) -> list[Finding]:
        cfg = self.config.connection_behavior
        if not cfg.enabled:
            return []
        findings: list[Finding] = []
        for c in result.connections:
            if c.protocol not in ("TCP", "UDP"):
                continue
            if (f := self._upload(c)) is not None:
                findings.append(f)
            if (f := self._cleartext(c)) is not None:
                findings.append(f)
        return findings

    def _upload(self, c: Connection) -> Finding | None:
        cfg = self.config.connection_behavior
        up, down = c.bytes_client_to_server, c.bytes_server_to_client
        if up < cfg.min_upload_bytes:
            return None
        if not (is_private_ip(c.client_ip) and not is_private_ip(c.server_ip)):
            return None
        asym = up / max(down, 1)
        if asym < cfg.min_asymmetry:
            return None
        uncommon = c.server_port is not None and c.server_port not in WELL_KNOWN_PORTS
        w = cfg.weights
        factors = [
            ("volume", ramp(up, cfg.min_upload_bytes, cfg.strong_upload_bytes), w["volume"], f"{_mb(up)} sent"),
            ("asymmetry", ramp(asym, cfg.min_asymmetry, cfg.strong_asymmetry), w["asymmetry"],
             f"sent/received ratio {asym:.0f}:1"),
            ("uncommon_port", 1.0 if uncommon else 0.0, w["uncommon_port"],
             f"port {c.server_port} {'has no well-known service' if uncommon else 'is a well-known service port'}"),
        ]
        return self.build(
            type=FindingType.UNUSUAL_OUTBOUND_TRANSFER, factors=factors, max_severity=cfg.max_severity,
            title=f"Large outbound transfer from {c.client_ip} to {c.server_ip}",
            description=(
                f"{c.client_ip} sent {_mb(up)} to public host {c.server_ip}:{c.server_port} while receiving only "
                f"{_mb(down)} ({asym:.0f}:1). This is consistent with a possible data upload or exfiltration, but "
                f"backups, cloud sync and software uploads look identical; it requires investigation."
            ),
            evidence={"protocol": c.protocol, "client": f"{c.client_ip}:{c.client_port}",
                      "server": f"{c.server_ip}:{c.server_port}", "bytes_sent": up, "bytes_received": down,
                      "asymmetry_ratio": round(asym, 1), "duration_seconds": c.duration_seconds,
                      "server_port_is_well_known": not uncommon},
            reasoning=[f"Upload of {_mb(up)} exceeds {_mb(cfg.min_upload_bytes)}.",
                       f"Sent/received ratio {asym:.0f}:1 exceeds {cfg.min_asymmetry:.0f}:1.",
                       "Private client to public server (outbound)."],
            caveats=["Backups, cloud sync, video calls and software publishing are legitimate heavy uploads."],
            recommendation=f"Confirm with the owner of {c.client_ip} whether this upload is expected; check the destination's ownership and the process responsible.",
            source_ip=c.client_ip, destination_ip=c.server_ip, key=f"{c.client_ip}:{c.client_port}>{c.server_ip}:{c.server_port}",
            first_seen=c.start_time, last_seen=c.end_time,
        )

    def _cleartext(self, c: Connection) -> Finding | None:
        cfg = self.config.connection_behavior
        name = cfg.cleartext_ports.get(c.server_port or -1)
        if c.protocol != "TCP" or name is None or not c.handshake_complete or c.packets < cfg.cleartext_min_packets:
            return None
        public = not is_private_ip(c.server_ip)
        w = cfg.cleartext_weights
        factors = [
            ("traffic", ramp(c.packets, cfg.cleartext_min_packets, cfg.cleartext_strong_packets), w["traffic"],
             f"{c.packets} packets in the session"),
            ("public_server", 1.0 if public else 0.0, w["public_server"],
             "server is public" if public else "server is on a private network"),
        ]
        return self.build(
            type=FindingType.CLEARTEXT_PROTOCOL, factors=factors, max_severity=cfg.cleartext_max_severity,
            title=f"Cleartext {name} session between {c.client_ip} and {c.server_ip}",
            description=(
                f"An established {name} session ({c.packets} packets) between {c.client_ip} and "
                f"{c.server_ip}:{c.server_port} was observed. {name} sends data and often credentials unencrypted, "
                f"so this is a possible exposure risk and requires investigation."
            ),
            evidence={"protocol_name": name, "client": f"{c.client_ip}:{c.client_port}",
                      "server": f"{c.server_ip}:{c.server_port}", "packets": c.packets, "bytes": c.bytes,
                      "server_is_public": public},
            reasoning=[f"Completed TCP handshake to port {c.server_port} ({name}) with {c.packets} packets."],
            caveats=["Legacy lab or device-management networks may use these protocols by design.",
                     "The port number alone does not prove which protocol is carried."],
            recommendation=f"Check whether {name} is expected here and whether an encrypted alternative (SSH, SFTP, TLS) is available.",
            source_ip=c.client_ip, destination_ip=c.server_ip, key=f"{c.client_ip}>{c.server_ip}:{c.server_port}",
            first_seen=c.start_time, last_seen=c.end_time,
        )
