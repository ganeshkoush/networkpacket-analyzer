"""Streaming PCAP/PCAPNG parser.

Reads a capture one packet at a time with Scapy and converts each packet into a
small :class:`PacketRecord`. Analyzers consume these records and keep only
aggregates, so memory use does not grow with capture size.

Malformed packets never abort parsing: they are counted and yielded as a minimal
``Malformed`` record (timestamp and size only) so totals stay honest.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, dnsqtypes
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapReader

logger = logging.getLogger(__name__)

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microsecond
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microsecond
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanosecond
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_NON_PROTOCOL_LAYERS = {"Raw", "Padding"}


class CaptureError(Exception):
    """Base class for capture-reading problems."""


class InvalidCaptureError(CaptureError):
    """The file exists but is not a readable PCAP/PCAPNG capture."""


@dataclass(slots=True, frozen=True)
class DnsAnswer:
    """One A/AAAA/CNAME answer record (other record types are not kept)."""

    rtype: str  # "A" | "AAAA" | "CNAME"
    name: str
    data: str  # IP address text, or the CNAME target
    ttl: int | None


MAX_DNS_ANSWERS = 32


@dataclass(slots=True)
class DnsInfo:
    """Fields of a DNS message relevant to analysis."""

    transaction_id: int
    is_response: bool
    qname: str | None
    qtype: str | None
    rcode: str | None
    answer_count: int
    answers: tuple[DnsAnswer, ...] = ()


@dataclass(slots=True)
class PacketRecord:
    """Flat, minimal view of one packet. Any field may be ``None`` if absent."""

    index: int
    timestamp: float
    size: int  # original on-the-wire length
    protocol: str  # most specific protocol label, e.g. "DNS", "TCP", "ARP", "Malformed"
    layers: tuple[str, ...] = ()
    ip_version: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    transport: str | None = None  # "TCP" | "UDP" | "ICMP" | "ICMPv6"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    payload_len: int | None = None
    # Content-free classification of the first bytes of a TCP payload (see ``classify_tcp_payload``).
    app_hint: str | None = None
    dns: DnsInfo | None = None
    eth_src: str | None = None
    arp_op: int | None = None  # 1 = request, 2 = reply
    arp_sender_mac: str | None = None
    arp_sender_ip: str | None = None
    arp_target_mac: str | None = None
    arp_target_ip: str | None = None
    snaplen_truncated: bool = False
    malformed: bool = False


_HTTP_REQUEST = re.compile(rb"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/1\.[01]\r?\n")
_HTTP_RESPONSE = re.compile(rb"HTTP/1\.[01] (\d{3})[ \r\n]")
HTTP_REQUEST, HTTP_RESPONSE, HTTP_CONTINUE = "http_request", "http_response", "http_continue"
TLS_CLIENT_HELLO, TLS_SERVER_HELLO = "tls_client_hello", "tls_server_hello"
_HINT_BYTES = 512


def classify_tcp_payload(head: bytes) -> str | None:
    """Recognise (without keeping any content) the start of cleartext HTTP/1.x or a TLS handshake.

    Only the *kind* of message is returned: ``http_request``, ``http_response``,
    ``http_continue`` (1xx interim response), ``tls_client_hello`` or ``tls_server_hello``.
    A request needs a complete, well-formed request line; anything else is not classified, so a
    hint means the traffic really is visible HTTP/TLS, not a guess from the port number.
    """
    if not head:
        return None
    first = head[0]
    if first == 0x16 and len(head) >= 9 and head[1] == 3 and head[2] <= 4:  # TLS handshake record
        record_len = (head[3] << 8) | head[4]
        hs_len = (head[6] << 16) | (head[7] << 8) | head[8]
        if head[5] in (1, 2) and 4 + hs_len <= record_len <= 16384 + 2048:
            return TLS_CLIENT_HELLO if head[5] == 1 else TLS_SERVER_HELLO
        return None
    if first == 0x48:  # "H"
        m = _HTTP_RESPONSE.match(head)
        if m:
            return HTTP_CONTINUE if m.group(1).startswith(b"1") else HTTP_RESPONSE
        return None
    if _HTTP_REQUEST.match(head):
        return HTTP_REQUEST
    return None


def detect_format(path: Path) -> str:
    """Return ``"pcap"`` or ``"pcapng"`` from the file's magic bytes.

    Raises:
        FileNotFoundError: path does not exist or is not a file.
        InvalidCaptureError: file is too short or has an unknown signature.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {path}")
    with path.open("rb") as fh:
        magic = fh.read(4)
    if len(magic) < 4:
        raise InvalidCaptureError(f"{path.name}: file is empty or too short to be a capture")
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise InvalidCaptureError(f"{path.name}: not a PCAP or PCAPNG file (unrecognised signature)")


def _extract_answers(dns: Any) -> tuple[DnsAnswer, ...]:
    """A/AAAA/CNAME answers of a response. Never raises: a bad record is skipped, not fatal."""
    out: list[DnsAnswer] = []
    try:
        count = min(int(dns.ancount), MAX_DNS_ANSWERS)
        an = dns.an
        for i in range(count):
            rr = an[i]
            rtype = {1: "A", 28: "AAAA", 5: "CNAME"}.get(int(rr.type))
            if rtype is None:
                continue
            raw = rr.rdata
            data = (raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)).rstrip(".").lower()
            name = rr.rrname.decode("utf-8", "replace") if isinstance(rr.rrname, bytes) else str(rr.rrname)
            out.append(DnsAnswer(rtype, name.rstrip(".").lower(), data, int(rr.ttl)))
    except Exception:
        logger.debug("Could not read DNS answer records", exc_info=True)
    return tuple(out)


def _extract_dns(pkt: Any) -> DnsInfo | None:
    dns = pkt.getlayer(DNS)
    if dns is None:
        return None
    qname: str | None = None
    qtype: str | None = None
    qd = dns.qd
    question = None
    if isinstance(qd, list):
        question = qd[0] if qd else None
    elif qd is not None:
        question = qd
    if question is not None:
        raw = question.qname
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        qname = str(raw).rstrip(".").lower() or "."
        qtype = str(dnsqtypes.get(question.qtype, question.qtype))
    rcode = DNS_RCODES.get(int(dns.rcode), f"RCODE{int(dns.rcode)}") if dns.qr else None
    return DnsInfo(
        transaction_id=int(dns.id),
        is_response=bool(dns.qr),
        qname=qname,
        qtype=qtype,
        rcode=rcode,
        answer_count=int(dns.ancount),
        answers=_extract_answers(dns) if dns.qr and int(dns.ancount) else (),
    )


def _protocol_label(layer_names: list[str], dns: DnsInfo | None, transport: str | None) -> str:
    if dns is not None:
        return "DNS"
    if transport is not None:
        return transport
    for name in reversed(layer_names):
        if name in _NON_PROTOCOL_LAYERS:
            continue
        if name == "IP":
            return "IPv4"
        if name.startswith("ICMPv6"):
            return "ICMPv6"
        return name
    return "Unknown"


def extract_record(index: int, pkt: Any) -> PacketRecord:
    """Convert a Scapy packet to a :class:`PacketRecord`.

    May raise on badly malformed packets; :class:`PcapParser` handles that.
    """
    timestamp = float(pkt.time)
    wirelen = getattr(pkt, "wirelen", None)
    size = int(wirelen) if wirelen else len(pkt)
    layer_names = [layer.__name__ for layer in pkt.layers()]
    names = set(layer_names)

    rec = PacketRecord(
        index=index,
        timestamp=timestamp,
        size=size,
        protocol="Unknown",
        snaplen_truncated=bool(wirelen and len(pkt) < int(wirelen)),
    )

    ip_hdr = None
    ip_payload_len: int | None = None
    if "IP" in names:
        ip_hdr = pkt[IP]
        rec.ip_version = 4
        rec.src_ip, rec.dst_ip = str(ip_hdr.src), str(ip_hdr.dst)
        if ip_hdr.len:
            ip_payload_len = int(ip_hdr.len) - int(ip_hdr.ihl or 5) * 4
    elif "IPv6" in names:
        ip_hdr = pkt[IPv6]
        rec.ip_version = 6
        rec.src_ip, rec.dst_ip = str(ip_hdr.src), str(ip_hdr.dst)
        ip_payload_len = int(ip_hdr.plen) if ip_hdr.plen else None

    if "TCP" in names:
        tcp = pkt[TCP]
        rec.transport = "TCP"
        rec.src_port, rec.dst_port = int(tcp.sport), int(tcp.dport)
        rec.tcp_flags = int(tcp.flags)
        rec.tcp_seq, rec.tcp_ack = int(tcp.seq), int(tcp.ack)
        if ip_payload_len is not None:
            rec.payload_len = max(0, ip_payload_len - int(tcp.dataofs or 5) * 4)
        else:
            rec.payload_len = len(tcp.payload)
        if rec.payload_len:
            rec.app_hint = classify_tcp_payload(bytes(tcp.payload)[:_HINT_BYTES])
    elif "UDP" in names:
        udp = pkt[UDP]
        rec.transport = "UDP"
        rec.src_port, rec.dst_port = int(udp.sport), int(udp.dport)
        rec.payload_len = max(0, int(udp.len) - 8) if udp.len else len(udp.payload)
        rec.dns = _extract_dns(pkt)
    elif "ICMP" in names:
        rec.transport = "ICMP"
    elif any(n.startswith("ICMPv6") for n in names):
        rec.transport = "ICMPv6"

    if "Ether" in names:
        rec.eth_src = str(pkt[Ether].src).lower()
    if "ARP" in names:
        arp = pkt[ARP]
        rec.arp_op = int(arp.op)
        rec.arp_sender_mac = str(arp.hwsrc).lower()
        rec.arp_sender_ip = str(arp.psrc)
        rec.arp_target_mac = str(arp.hwdst).lower()
        rec.arp_target_ip = str(arp.pdst)
        rec.protocol = "ARP"
    else:
        rec.protocol = _protocol_label(layer_names, rec.dns, rec.transport)

    layers: list[str] = []
    if rec.ip_version:
        layers.append(f"IPv{rec.ip_version}")
    if rec.transport:
        layers.append(rec.transport)
    if rec.dns:
        layers.append("DNS")
    if "ARP" in names:
        layers.append("ARP")
    rec.layers = tuple(layers)
    return rec


class PcapParser:
    """Iterate :class:`PacketRecord` objects from a PCAP/PCAPNG file.

    Counters (``packets_read``, ``malformed_packets``, ``snaplen_truncated_packets``,
    ``read_error``) are updated as iteration proceeds.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.format = detect_format(self.path)  # validates the file up front
        self.packets_read = 0
        self.malformed_packets = 0
        self.snaplen_truncated_packets = 0
        self.read_error: str | None = None
        self._reader: Any = None
        self._last_bytes = 0

    @property
    def bytes_read(self) -> int:
        """Approximate file offset consumed so far (for progress reporting); 0 if unknown."""
        try:
            self._last_bytes = int(self._reader.f.tell())
        except Exception:  # reader closed or not started: report the last known offset
            pass
        return self._last_bytes

    def __iter__(self) -> Iterator[PacketRecord]:
        try:
            reader = PcapReader(str(self.path))
        except Exception as exc:  # scapy raises various types on bad headers
            raise InvalidCaptureError(f"{self.path.name}: cannot open capture: {exc}") from exc

        self._reader = reader
        index = 0
        try:
            while True:
                try:
                    pkt = next(reader)
                except StopIteration:
                    break
                except Exception as exc:  # truncated/corrupt file: cannot resume
                    self.read_error = f"{type(exc).__name__}: {exc}"
                    logger.error("Stopped reading %s after %d packets: %s",
                                 self.path.name, index, self.read_error)
                    break
                index += 1
                self.packets_read += 1
                try:
                    rec = extract_record(index, pkt)
                except Exception as exc:
                    self.malformed_packets += 1
                    logger.warning("Malformed packet #%d in %s: %s", index, self.path.name, exc)
                    rec = self._fallback_record(index, pkt)
                    if rec is None:
                        continue
                if rec.snaplen_truncated:
                    self.snaplen_truncated_packets += 1
                yield rec
        finally:
            _ = self.bytes_read  # remember the final offset before the file is closed
            try:
                reader.close()
            except Exception:  # pragma: no cover - best effort
                pass

    @staticmethod
    def _fallback_record(index: int, pkt: Any) -> PacketRecord | None:
        try:
            wirelen = getattr(pkt, "wirelen", None)
            return PacketRecord(
                index=index,
                timestamp=float(pkt.time),
                size=int(wirelen) if wirelen else len(pkt),
                protocol="Malformed",
                malformed=True,
            )
        except Exception:
            return None
