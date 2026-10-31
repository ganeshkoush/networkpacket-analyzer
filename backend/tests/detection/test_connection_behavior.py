from detection_helpers import assert_well_formed, blank_result
from app.detection import DetectionConfig, FindingType, Severity, detect_threats
from app.detection.config import ConnectionBehaviorConfig
from app.models.analysis import Connection

MIB = 1024 * 1024


def conn(up=0, down=0, client="10.0.0.5", server="93.184.216.34", port=4444, proto="TCP", packets=100,
         handshake=True):
    return Connection(
        protocol=proto, client_ip=client, client_port=50000, server_ip=server, server_port=port,
        packets=packets, bytes=up + down, packets_client_to_server=packets // 2,
        packets_server_to_client=packets // 2, bytes_client_to_server=up, bytes_server_to_client=down,
        start_time=1.0, end_time=61.0, duration_seconds=60.0,
        handshake_complete=handshake if proto == "TCP" else None,
    )


def run(*conns, config=None):
    return detect_threats(blank_result(connections=list(conns)), config)


def of_type(findings, t):
    return [f for f in findings if f.type == t]


def test_large_asymmetric_upload_detected():
    (f,) = of_type(run(conn(up=200 * MIB, down=1 * MIB)), FindingType.UNUSUAL_OUTBOUND_TRANSFER)
    assert f.source_ip == "10.0.0.5" and f.destination_ip == "93.184.216.34"
    assert f.evidence["bytes_sent"] == 200 * MIB and f.evidence["asymmetry_ratio"] == 200.0
    assert f.evidence["server_port_is_well_known"] is False
    assert f.severity.rank <= Severity.MEDIUM.rank
    assert_well_formed(f)


def test_common_port_scores_lower_than_uncommon_port():
    odd = of_type(run(conn(up=200 * MIB, down=1 * MIB, port=4444)), FindingType.UNUSUAL_OUTBOUND_TRANSFER)[0]
    https = of_type(run(conn(up=200 * MIB, down=1 * MIB, port=443)), FindingType.UNUSUAL_OUTBOUND_TRANSFER)[0]
    assert odd.confidence > https.confidence


def test_normal_and_false_positive_transfers_not_flagged():
    cases = [
        conn(up=1 * MIB, down=500 * MIB, port=443),            # download
        conn(up=200 * MIB, down=150 * MIB, port=443),          # balanced (video call / sync)
        conn(up=5 * MIB, down=0, port=4444),                   # too small
        conn(up=200 * MIB, down=1 * MIB, server="10.0.0.77"),  # internal server (backup to NAS)
        conn(up=200 * MIB, down=1 * MIB, client="93.184.216.35", server="93.184.216.34"),  # not from a private client
    ]
    for c in cases:
        assert of_type(run(c), FindingType.UNUSUAL_OUTBOUND_TRANSFER) == [], c


def test_upload_threshold_is_configurable():
    c = conn(up=20 * MIB, down=1 * MIB)
    assert of_type(run(c), FindingType.UNUSUAL_OUTBOUND_TRANSFER)
    cfg = DetectionConfig(connection_behavior=ConnectionBehaviorConfig(min_upload_bytes=100 * MIB))
    assert of_type(run(c, config=cfg), FindingType.UNUSUAL_OUTBOUND_TRANSFER) == []


def test_zero_download_does_not_divide_by_zero():
    (f,) = of_type(run(conn(up=50 * MIB, down=0)), FindingType.UNUSUAL_OUTBOUND_TRANSFER)
    assert f.evidence["asymmetry_ratio"] == 50 * MIB


def test_cleartext_session_detected_and_low_severity():
    (f,) = of_type(run(conn(up=2000, down=3000, port=23, packets=60, server="10.0.0.2")), FindingType.CLEARTEXT_PROTOCOL)
    assert f.evidence["protocol_name"] == "Telnet" and f.severity.rank <= Severity.LOW.rank
    assert_well_formed(f)


def test_cleartext_over_public_server_scores_higher():
    private = of_type(run(conn(port=21, packets=60, server="10.0.0.2")), FindingType.CLEARTEXT_PROTOCOL)[0]
    public = of_type(run(conn(port=21, packets=60, server="93.184.216.40")), FindingType.CLEARTEXT_PROTOCOL)[0]
    assert public.confidence > private.confidence


def test_cleartext_edge_cases_not_flagged():
    assert of_type(run(conn(port=23, handshake=False)), FindingType.CLEARTEXT_PROTOCOL) == []  # never established
    assert of_type(run(conn(port=23, packets=4)), FindingType.CLEARTEXT_PROTOCOL) == []        # too short
    assert of_type(run(conn(port=22)), FindingType.CLEARTEXT_PROTOCOL) == []                   # SSH is encrypted
    assert of_type(run(conn(port=23, proto="UDP")), FindingType.CLEARTEXT_PROTOCOL) == []


def test_icmp_connections_ignored_and_no_connections_is_fine():
    assert run() == []
    assert run(conn(proto="ICMP", up=500 * MIB, down=0)) == []
