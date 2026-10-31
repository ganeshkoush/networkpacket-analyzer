import pytest

import pcap_factory as pf
from app.analysis import analyze_pcap
from app.analysis import pcap_parser
from app.analysis.pcap_parser import InvalidCaptureError, PcapParser, detect_format


def test_empty_pcap_has_zero_packets(make_pcap):
    result = analyze_pcap(make_pcap([]))
    assert result.metadata.packets_read == 0
    assert result.packet_statistics.total_packets == 0
    assert result.packet_statistics.mean_packet_size is None
    assert result.metadata.duration_seconds == 0
    assert result.timeline == [] and result.connections == []
    assert any("no packets" in w for w in result.metadata.warnings)


def test_zero_byte_file_rejected(tmp_path):
    f = tmp_path / "empty.pcap"
    f.write_bytes(b"")
    with pytest.raises(InvalidCaptureError):
        analyze_pcap(f)


def test_non_capture_file_rejected(tmp_path):
    f = tmp_path / "notes.pcap"
    f.write_text("this is definitely not a capture file")
    with pytest.raises(InvalidCaptureError):
        analyze_pcap(f)


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze_pcap(tmp_path / "nope.pcap")


def test_directory_is_not_a_capture(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze_pcap(tmp_path)


def test_format_detection(make_pcap, tmp_path):
    assert detect_format(make_pcap([pf.arp()])) == "pcap"
    assert detect_format(pf.write_pcapng(tmp_path / "x.pcapng", [pf.arp()])) == "pcapng"


def test_pcapng_is_analyzed(tmp_path):
    path = pf.write_pcapng(tmp_path / "x.pcapng", pf.tcp_session())
    result = analyze_pcap(path)
    assert result.metadata.capture_format == "pcapng"
    assert result.metadata.packets_read == 7
    assert result.connection_summary.tcp_handshakes_complete == 1


def test_capture_cut_inside_last_packet_data_still_analyzed(make_pcap, tmp_path):
    pkts = pf.tcp_session()
    data = make_pcap(pkts).read_bytes()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(data[:-10])  # chop the tail of the last packet's data
    result = analyze_pcap(cut)  # must not raise
    assert result.metadata.packets_read >= 6
    assert result.tcp_statistics.total_packets >= 6


def test_capture_cut_inside_record_header_keeps_earlier_packets(make_pcap, tmp_path):
    pkts = pf.tcp_session()
    data = make_pcap(pkts).read_bytes()
    last_record = 16 + len(bytes(pkts[-1]))
    cut = tmp_path / "cut2.pcap"
    cut.write_bytes(data[: len(data) - last_record + 7])  # 7 bytes of the last record header remain
    result = analyze_pcap(cut)
    assert result.metadata.packets_read == 6
    assert result.packet_statistics.total_packets == 6


def test_header_only_garbage_body(make_pcap, tmp_path):
    path = make_pcap([pf.arp()])
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(path.read_bytes()[:24] + b"\xff" * 200)  # valid global header, junk records
    result = analyze_pcap(bad)  # must not raise
    assert result.metadata.packets_read >= 0


def test_malformed_packet_is_counted_not_fatal(make_pcap, monkeypatch):
    path = make_pcap(pf.tcp_session())
    real = pcap_parser.extract_record

    def flaky(index, pkt):
        if index == 3:
            raise ValueError("boom")
        return real(index, pkt)

    monkeypatch.setattr(pcap_parser, "extract_record", flaky)
    result = analyze_pcap(path)
    assert result.metadata.malformed_packets == 1
    assert result.packet_statistics.total_packets == 7  # still counted by size/time
    assert {p.protocol: p.packets for p in result.protocol_statistics.distribution}["Malformed"] == 1


def test_packet_with_missing_fields_does_not_crash(make_pcap):
    # raw bytes that are not a valid Ethernet/IP frame at all
    from scapy.packet import Raw
    pkt = pf.stamp(Raw(b"\x01\x02\x03"), pf.T0)
    result = analyze_pcap(make_pcap([pkt, pf.arp(ts=pf.T0 + 1)]))
    assert result.packet_statistics.total_packets == 2


def test_failing_analyzer_is_isolated(make_pcap, monkeypatch):
    from app.analysis import service

    def explode(self, pkt):
        raise RuntimeError("bad analyzer")

    monkeypatch.setattr(service.DnsAnalyzer, "add", explode)
    result = analyze_pcap(make_pcap(pf.tcp_session()))
    assert result.tcp_statistics.total_packets == 7
    assert any("dns" in w for w in result.metadata.warnings)


def test_parser_counters(make_pcap):
    parser = PcapParser(make_pcap(pf.tcp_session()))
    assert len(list(parser)) == 7
    assert parser.packets_read == 7 and parser.malformed_packets == 0


def test_read_error_midway_is_reported_not_raised(make_pcap, monkeypatch):
    real_reader = pcap_parser.PcapReader

    class Exploding:
        def __init__(self, path):
            self._inner = real_reader(path)
            self._n = 0

        def __next__(self):
            self._n += 1
            if self._n > 3:
                raise OSError("disk went away")
            return next(self._inner)

        def close(self):
            self._inner.close()

    monkeypatch.setattr(pcap_parser, "PcapReader", Exploding)
    result = analyze_pcap(make_pcap(pf.tcp_session()))
    assert result.metadata.packets_read == 3
    assert "disk went away" in result.metadata.read_error
    assert any("ended unexpectedly" in w for w in result.metadata.warnings)
