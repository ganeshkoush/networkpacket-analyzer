"""Matching OS process snapshots to observed connections, and the per-domain application view. Mocked process information."""
import threading
import time

import pytest

from app.models.analysis import Connection
from app.models.process import ProcessConnectionMapping, ProcessSnapshot
from app.platform.base import ProcessConnectionSource, ProcessSourceError, UnsupportedProcessSource
from app.services import process_mapper as pm
from app.services.process_mapper import ProcessMapper, match_connections
from detection_helpers import T0, blank_result

LOCAL = "192.168.1.10"
UNAVAILABLE = "Process information unavailable"


def conn(cid, sport, server="140.82.112.3", dport=443, *, start=T0 + 10, end=T0 + 20, proto="TCP", client=LOCAL, domain="github.com"):
    return Connection(id=cid, protocol=proto, client_ip=client, client_port=sport, server_ip=server, server_port=dport, packets=10, bytes=1000,
                      packets_client_to_server=5, packets_server_to_client=5, bytes_client_to_server=500, bytes_server_to_client=500,
                      start_time=start, end_time=end, duration_seconds=end - start, domain=domain)


def mapping(name, pid, sport, server="140.82.112.3", dport=443, *, ts=T0 + 15, app=None, proto="TCP", lip=LOCAL, rip="__same__", conf="HIGH"):
    return ProcessConnectionMapping(process_name=name, pid=pid, application=app, local_ip=lip, local_port=sport,
                                    remote_ip=server if rip == "__same__" else rip, remote_port=dport if rip == "__same__" else None,
                                    protocol=proto, timestamp=ts, confidence=conf)


def snap(*mappings, ts=T0 + 15):
    return ProcessSnapshot(timestamp=ts, platform="macOS", mappings=list(mappings), processes=len({m.pid for m in mappings}))


# ------------------------------------------------------------------ matching
def test_exact_endpoint_pair_matches_with_high_confidence():
    m = match_connections([conn("c1", 50000)], [snap(mapping("Code Helper", 1020, 50000, app="Visual Studio Code"))])
    assert set(m) == {"c1"}
    assert (m["c1"].process_name, m["c1"].pid, m["c1"].application, m["c1"].confidence) == ("Code Helper", 1020, "Visual Studio Code", "HIGH")
    assert m["c1"].snapshots_matched == 1 and not m["c1"].ambiguous and "exactly these" in m["c1"].reason


def test_matches_either_way_round():
    flipped = Connection(**{**conn("c1", 50000).model_dump(), "client_ip": "140.82.112.3", "client_port": 443, "server_ip": LOCAL, "server_port": 50000})
    assert "c1" in match_connections([flipped], [snap(mapping("curl", 7, 50000))])


def test_ip_notation_differences_do_not_prevent_a_match():
    c = conn("c1", 50000, server="2607:6BC0:0:0:0:0:0:10", client="2405:201:c40b:10b0:0:0:0:1")
    s = snap(mapping("Chrome", 5, 50000, server="2607:6bc0::10", lip="2405:201:c40b:10b0::1"))
    assert "c1" in match_connections([c], [s])


def test_a_different_remote_port_or_address_is_never_matched():
    s = snap(mapping("Chrome", 5, 50000, dport=8443))
    assert match_connections([conn("c1", 50000)], [s]) == {}
    assert match_connections([conn("c1", 50000)], [snap(mapping("Chrome", 5, 50000, server="1.1.1.1"))]) == {}
    assert match_connections([conn("c1", 50000)], [snap(mapping("Chrome", 5, 50000, proto="UDP"))]) == {}


def test_snapshots_taken_when_the_connection_was_not_active_are_not_used():
    c = conn("c1", 50000, start=T0 + 10, end=T0 + 20)
    for ts in (T0 + 100, T0 - 100, T0 + 22.5, T0 + 7.5):   # long after, long before, just beyond the 2 s slack
        assert match_connections([c], [snap(mapping("Chrome", 5, 50000, ts=ts), ts=ts)]) == {}, ts


def test_a_snapshot_just_outside_the_connections_lifetime_is_a_weaker_match():
    c = conn("c1", 50000, start=T0 + 10, end=T0 + 20)
    inside = match_connections([c], [snap(mapping("Chrome", 5, 50000), ts=T0 + 15)])["c1"]
    edge = match_connections([c], [snap(mapping("Chrome", 5, 50000, ts=T0 + 21), ts=T0 + 21)])["c1"]
    assert inside.confidence == "HIGH" and edge.confidence == "MEDIUM"


def test_the_process_seen_in_most_snapshots_wins_and_a_conflict_is_marked_ambiguous_and_low():
    snaps = [snap(mapping("A", 1, 50000, ts=T0 + 12), ts=T0 + 12), snap(mapping("B", 2, 50000, ts=T0 + 14), ts=T0 + 14), snap(mapping("B", 2, 50000, ts=T0 + 16), ts=T0 + 16)]
    m = match_connections([conn("c1", 50000)], snaps)["c1"]
    assert (m.process_name, m.snapshots_matched, m.ambiguous, m.confidence) == ("B", 2, True, "LOW") and "Several processes" in m.reason


def test_a_socket_bound_to_a_local_port_only_is_a_low_confidence_match():
    udp = conn("u1", 56044, server="142.250.80.46", proto="UDP")
    bound = ProcessConnectionMapping(process_name="Chrome", pid=5, local_ip=None, local_port=56044, remote_ip=None, remote_port=None, protocol="UDP", timestamp=T0 + 15, confidence="LOW")
    m = match_connections([udp], [snap(bound)])["u1"]
    assert m.confidence == "LOW" and "does not prove" in m.reason
    other_port = bound.model_copy(update={"local_port": 1234})
    assert match_connections([udp], [snap(other_port)]) == {}
    wrong_ip = bound.model_copy(update={"local_ip": "10.9.9.9"})
    assert match_connections([udp], [snap(wrong_ip)]) == {}


def test_a_full_match_beats_a_bound_port_match():
    bound = ProcessConnectionMapping(process_name="Other", pid=9, local_ip=None, local_port=50000, remote_ip=None, remote_port=None, protocol="TCP", timestamp=T0 + 15, confidence="LOW")
    m = match_connections([conn("c1", 50000)], [snap(bound, mapping("Chrome", 5, 50000))])["c1"]
    assert m.process_name == "Chrome" and m.confidence == "HIGH"


def test_other_protocols_and_portless_flows_are_ignored():
    icmp = Connection(**{**conn("i1", 1).model_dump(), "protocol": "ICMP", "client_port": None, "server_port": None})
    assert match_connections([icmp], [snap(mapping("ping", 3, 1))]) == {}


def test_no_snapshots_means_no_matches():
    assert match_connections([conn("c1", 50000)], []) == {}


# ------------------------------------------------------------------ the mapper service
class FakeSource(ProcessConnectionSource):
    platform, mechanism, permission_note = "macOS", "fake", "fake permission note"

    def __init__(self, mappings=(), fail=None):
        self.mappings, self.fail, self.calls = list(mappings), fail, 0

    def snapshot(self, now):
        self.calls += 1
        if self.fail:
            raise self.fail
        return ProcessSnapshot(timestamp=now, platform="macOS", mappings=[m.model_copy(update={"timestamp": now}) for m in self.mappings],
                               processes=len({m.pid for m in self.mappings}))


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def test_status_before_and_after_a_snapshot():
    mapper = ProcessMapper(FakeSource([mapping("x", 1, 1)]), clock=Clock(T0))
    s = mapper.status()
    assert s.supported and s.platform == "macOS" and s.snapshots == 0 and s.last_snapshot_at is None and not s.watching and s.permission_note == "fake permission note"
    assert any("in memory only" in n for n in s.notes) and any("while the traffic is being captured" in n for n in s.notes)
    mapper.snapshot()
    s = mapper.status()
    assert s.snapshots == 1 and s.first_snapshot_at == s.last_snapshot_at == T0


def test_nothing_is_queried_until_asked():
    src = FakeSource()
    mapper = ProcessMapper(src)
    mapper.status()
    mapper.snapshots_between(0, 1)
    assert src.calls == 0


def test_clear_forgets_everything_and_the_buffer_is_bounded():
    mapper = ProcessMapper(FakeSource([mapping("x", 1, 1)]), clock=Clock(T0), max_snapshots=3)
    for _ in range(5):
        mapper.snapshot()
    assert mapper.status().snapshots == 3 and mapper.clear() == 3 and mapper.status().snapshots == 0


def test_a_failing_os_query_is_reported_and_stores_nothing():
    mapper = ProcessMapper(FakeSource(fail=ProcessSourceError("lsof did not answer")), clock=Clock(T0))
    with pytest.raises(ProcessSourceError):
        mapper.snapshot()
    assert mapper.status().snapshots == 0


def test_unsupported_platforms_cannot_watch_and_report_unsupported():
    mapper = ProcessMapper(UnsupportedProcessSource("Windows"))
    assert not mapper.status().supported
    with pytest.raises(ProcessSourceError):
        mapper.start_watch()


def test_a_watch_samples_repeatedly_until_stopped_and_records_errors(monkeypatch):
    monkeypatch.setattr(pm, "MIN_INTERVAL_SECONDS", 0.01)
    src = FakeSource([mapping("x", 1, 1)])
    mapper = ProcessMapper(src)
    mapper.start_watch(interval_seconds=0.01)
    assert mapper.status().watching
    deadline = time.time() + 5
    while src.calls < 3 and time.time() < deadline:
        time.sleep(0.01)
    mapper.stop_watch()
    assert src.calls >= 3 and not mapper.status().watching and mapper.status().snapshots >= 3
    after = src.calls
    time.sleep(0.05)
    assert src.calls == after                                   # really stopped

    failing = ProcessMapper(FakeSource(fail=ProcessSourceError("lsof failed")))
    failing.start_watch(interval_seconds=0.01)
    time.sleep(0.1)
    failing.stop_watch()
    assert failing.status().last_error == "lsof failed" and failing.status().snapshots == 0


def test_a_watch_stops_by_itself_after_its_maximum_duration(monkeypatch):
    monkeypatch.setattr(pm, "MIN_INTERVAL_SECONDS", 0.01)
    mapper = ProcessMapper(FakeSource([mapping("x", 1, 1)]))
    mapper.start_watch(interval_seconds=0.01, max_seconds=0.15)
    deadline = time.time() + 5
    while mapper.status().watching and time.time() < deadline:
        time.sleep(0.02)
    assert not mapper.status().watching


def test_starting_a_second_watch_does_not_start_a_second_thread(monkeypatch):
    monkeypatch.setattr(pm, "MIN_INTERVAL_SECONDS", 0.01)
    mapper = ProcessMapper(FakeSource([mapping("x", 1, 1)]))
    mapper.start_watch(interval_seconds=0.05)
    before = {t.ident for t in threading.enumerate() if t.name == "packetmind-process-watch"}
    mapper.start_watch(interval_seconds=0.05)
    assert {t.ident for t in threading.enumerate() if t.name == "packetmind-process-watch"} == before
    mapper.stop_watch()


# ------------------------------------------------------------------ the per-domain application view
def domain_result(connections, first=T0, last=T0 + 60):
    r = blank_result(connections=connections)
    r.metadata.first_packet_time, r.metadata.last_packet_time = first, last
    return r


def github_connections():
    """The spec's example: 12 connections from VS Code and 6 from Chrome to github.com."""
    conns = [conn(f"v{i}", 50000 + i) for i in range(12)] + [conn(f"c{i}", 51000 + i) for i in range(6)]
    maps = [mapping("Code Helper (Plugin)" if i % 2 else "Code Helper", 1000 + i % 2, 50000 + i, app="Visual Studio Code") for i in range(12)]
    maps += [mapping("Google Chrome Helper", 2000, 51000 + i, app="Google Chrome") for i in range(6)]
    return conns, maps


def mapper_with(maps, clock_t=T0 + 15):
    mapper = ProcessMapper(FakeSource(maps), clock=Clock(clock_t))
    mapper.snapshot()
    return mapper


def test_the_domain_lists_applications_with_connection_counts():
    conns, maps = github_connections()
    out = mapper_with(maps).applications_for_domain(domain_result(conns), "github.com")
    assert out.status == "available" and out.connections_considered == 18 and out.connections_matched == 18 and out.connections_unmatched == 0
    assert [(a.name, a.kind, a.connections) for a in out.applications] == [("Visual Studio Code", "application", 12), ("Google Chrome", "application", 6)]
    code = out.applications[0]
    assert code.process_names == ["Code Helper", "Code Helper (Plugin)"] and code.pids == [1000, 1001] and code.confidence_counts == {"HIGH": 12}
    assert out.snapshots_used == 1 and "not from the captured packets" in out.source_note and out.permission_note == "fake permission note"


def test_helper_processes_group_under_their_application_but_plain_executables_keep_their_own_name():
    conns = [conn("a", 50000), conn("b", 50001), conn("c", 50002)]
    maps = [mapping("Google Chrome Helper", 1, 50000, app="Google Chrome"), mapping("Google Chrome Helper (Renderer)", 2, 50001, app="Google Chrome"), mapping("curl", 3, 50002)]
    out = mapper_with(maps).applications_for_domain(domain_result(conns), "github.com")
    assert {(a.name, a.kind, a.connections) for a in out.applications} == {("Google Chrome", "application", 2), ("curl", "process", 1)}


def test_partly_matched_domains_say_which_connections_have_no_process_information():
    conns, maps = github_connections()
    out = mapper_with(maps[:12]).applications_for_domain(domain_result(conns), "github.com")   # Chrome's sockets are not in the snapshot
    assert out.status == "partial" and out.connections_matched == 12 and out.connections_unmatched == 6
    assert "6 of 18 connection(s) could not be matched: process information unavailable for them." in out.message


def test_unavailable_states_always_say_so_and_never_invent_an_application():
    conns, maps = github_connections()
    result = domain_result(conns)

    none_taken = ProcessMapper(FakeSource(maps), clock=Clock(T0 + 15)).applications_for_domain(result, "github.com")
    assert none_taken.status == "no_snapshots" and none_taken.message.startswith(UNAVAILABLE) and none_taken.applications == []
    assert "can't be taken retroactively" in none_taken.message

    late = mapper_with(maps, clock_t=T0 + 86_400).applications_for_domain(result, "github.com")  # snapshot a day after the capture
    assert late.status == "no_overlap" and late.message.startswith(UNAVAILABLE) and late.applications == [] and "none of the 1 snapshot(s)" in late.message

    elsewhere = mapper_with([mapping("Chrome", 5, 40000)]).applications_for_domain(result, "github.com")
    assert elsewhere.status == "no_matches" and elsewhere.message.startswith(UNAVAILABLE) and elsewhere.applications == [] and elsewhere.connections_unmatched == 18

    unsupported = ProcessMapper(UnsupportedProcessSource("Linux")).applications_for_domain(result, "github.com")
    assert unsupported.status == "unsupported" and unsupported.message.startswith(UNAVAILABLE) and "Linux" in unsupported.message


def test_a_capture_without_timestamps_cannot_be_matched():
    conns, maps = github_connections()
    r = domain_result(conns)
    r.metadata.first_packet_time = r.metadata.last_packet_time = None
    out = mapper_with(maps).applications_for_domain(r, "github.com")
    assert out.status == "no_overlap" and out.message.startswith(UNAVAILABLE)


def test_only_the_requested_domains_connections_are_considered():
    conns = [conn("g1", 50000), conn("y1", 50001, server="142.250.80.46", domain="youtube.com"), conn("n1", 50002, domain=None)]
    maps = [mapping("Chrome", 1, 50001, server="142.250.80.46", app="Google Chrome")]
    out = mapper_with(maps).applications_for_domain(domain_result(conns), "youtube.com")
    assert out.status == "available" and out.connections_considered == 1 and [a.name for a in out.applications] == ["Google Chrome"]


def test_snapshots_are_never_written_to_disk_or_the_database():
    import inspect

    source = inspect.getsource(pm)
    assert "sqlalchemy" not in source and "open(" not in source and "sqlite" not in source.lower() and "write_text" not in source
