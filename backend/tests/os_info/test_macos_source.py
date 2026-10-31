"""macOS process source: parsing real-shaped lsof/ps output, application names, and the allowlist of commands. No OS access."""
import subprocess

import pytest

from app.platform import UnsupportedProcessSource, get_process_source
from app.platform import macos
from app.platform.base import ProcessSourceError
from app.platform.macos import LSOF, PS, MacOSProcessSource, application_from_path, parse_lsof, parse_ps, run_command

NOW = 1_700_000_000.0

LSOF_OUT = """\
p1020
cCode Helper (Plugin)
f23
PTCP
n192.168.29.228:50520->4.150.223.106:443
TST=ESTABLISHED
f25
PTCP
n192.168.29.228:50521->140.82.112.3:443
TST=ESTABLISHED
p1045
cGoogle Chrome Helper
f37
PUDP
n[2405:201:c40b:10b0::1]:56044->[2607:6bc0::10]:443
f38
PUDP
n*:5353
p630
cControlCenter
f9
PTCP
n*:7000
TST=LISTEN
p2222
cdiscord helper
f3
PTCP
n[::ffff:10.0.0.5]:51000->[::ffff:162.159.135.232]:443
TST=ESTABLISHED
"""

PS_OUT = """\
 1020 /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)
 1045 /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/154/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper
  630 /System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter
 2222 /Applications/Discord.app/Contents/MacOS/Discord Helper
"""


def by(mappings, **kw):
    return [m for m in mappings if all(getattr(m, k) == v for k, v in kw.items())]


# ------------------------------------------------------------------ parsing
def test_parse_lsof_connected_tcp_udp_ipv6_wildcards_and_listeners():
    mappings, processes, truncated = parse_lsof(LSOF_OUT, NOW)
    assert processes == 4 and not truncated and len(mappings) == 6
    tcp = by(mappings, pid=1020, remote_port=443)[0]
    assert (tcp.process_name, tcp.local_ip, tcp.local_port, tcp.remote_ip, tcp.protocol, tcp.timestamp) == (
        "Code Helper (Plugin)", "192.168.29.228", 50520, "4.150.223.106", "TCP", NOW)
    assert tcp.confidence == "HIGH" and tcp.application is None  # application is added later, from ps
    quic = by(mappings, pid=1045, remote_ip="2607:6bc0::10")[0]
    assert quic.protocol == "UDP" and quic.local_ip == "2405:201:c40b:10b0::1" and quic.confidence == "MEDIUM"
    listener = by(mappings, pid=630)[0]
    assert (listener.local_ip, listener.local_port, listener.remote_ip, listener.remote_port, listener.confidence) == (None, 7000, None, None, "LOW")
    unconnected = by(mappings, local_port=5353)[0]
    assert unconnected.remote_ip is None and unconnected.confidence == "LOW" and unconnected.process_name == "Google Chrome Helper"


def test_ipv4_mapped_ipv6_addresses_are_normalised_to_ipv4():
    (m,) = by(parse_lsof(LSOF_OUT, NOW)[0], pid=2222)
    assert (m.local_ip, m.remote_ip) == ("10.0.0.5", "162.159.135.232")


@pytest.mark.parametrize("junk", [
    "", "garbage\nlines\n", "p12\nc\nPTCP\nn1.2.3.4:80->5.6.7.8:443\n",      # no command name
    "p12\ncfoo\nPICMP\nn1.2.3.4:80\n",                                        # not TCP/UDP
    "p12\ncfoo\nPTCP\nnnot-an-endpoint\n", "pXYZ\ncfoo\nPTCP\nn1.2.3.4:80->5.6.7.8:443\n",
    "cfoo\nPTCP\nn1.2.3.4:80->5.6.7.8:443\n",                                 # no pid
    "p12\ncfoo\nPTCP\nn1.2.3.4:80->weird\n",                                  # unparseable remote
])
def test_malformed_records_are_skipped_never_guessed(junk):
    assert parse_lsof(junk, NOW)[0] == []


def test_a_file_record_without_its_own_protocol_is_not_attributed_to_the_previous_one():
    out = "p12\ncfoo\nf3\nPTCP\nn1.2.3.4:80->5.6.7.8:443\nf4\nn9.9.9.9:1->8.8.8.8:2\n"  # second file has no P
    mappings, *_ = parse_lsof(out, NOW)
    assert [(m.local_port, m.remote_port) for m in mappings] == [(80, 443)]


def test_very_large_output_is_truncated_and_reported(monkeypatch):
    monkeypatch.setattr(macos, "MAX_MAPPINGS", 3)
    out = "p1\ncfoo\n" + "".join(f"f{i}\nPTCP\nn10.0.0.1:{1000 + i}->10.0.0.2:443\n" for i in range(10))
    mappings, _, truncated = parse_lsof(out, NOW)
    assert len(mappings) == 3 and truncated


# ------------------------------------------------------------------ application names (from the executable path)
@pytest.mark.parametrize("path,expected", [
    ("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/154/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper", "Google Chrome"),
    ("/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)", "Visual Studio Code"),
    ("/Applications/Discord.app/Contents/MacOS/Discord", "Discord"),
    ("/System/Applications/Safari.app/Contents/MacOS/Safari", "Safari"),
    ("/usr/bin/curl", None), ("/opt/homebrew/bin/node", None), ("", None),
    ("/Users/me/notes.application/run", None),      # ".application" is not an app bundle
    ("/Applications/.app/x", None),                 # an empty bundle name is not a name
])
def test_application_is_the_outermost_app_bundle_or_nothing(path, expected):
    assert application_from_path(path) == expected


def test_parse_ps_handles_paths_with_spaces_and_ignores_garbage():
    paths = parse_ps(PS_OUT + "not a line\n  abc /x\n 77\n")
    assert paths[1020].endswith("Code Helper (Plugin)") and paths[2222] == "/Applications/Discord.app/Contents/MacOS/Discord Helper" and len(paths) == 4


# ------------------------------------------------------------------ the source, with a mocked runner
class FakeRunner:
    def __init__(self, lsof=LSOF_OUT, ps=PS_OUT, ps_error=None):
        self.calls, self.lsof, self.ps, self.ps_error = [], lsof, ps, ps_error

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == LSOF:
            return self.lsof
        if self.ps_error:
            raise self.ps_error
        return self.ps


def test_snapshot_combines_sockets_with_application_names():
    snap = MacOSProcessSource(FakeRunner()).snapshot(NOW)
    assert snap.platform == "macOS" and snap.timestamp == NOW and snap.processes == 4 and not snap.truncated
    apps = {m.process_name: m.application for m in snap.mappings}
    assert apps == {"Code Helper (Plugin)": "Visual Studio Code", "Google Chrome Helper": "Google Chrome", "ControlCenter": "ControlCenter", "discord helper": "Discord"}
    assert all(m.timestamp == NOW for m in snap.mappings)


def test_only_two_fixed_read_only_commands_are_ever_run():
    runner = FakeRunner()
    MacOSProcessSource(runner).snapshot(NOW)
    assert [c[0] for c in runner.calls] == [LSOF, PS]
    assert LSOF == "/usr/sbin/lsof" and PS == "/bin/ps"                    # absolute paths: not resolved through $PATH
    lsof = runner.calls[0]
    assert "-n" in "".join(lsof) and lsof[-2:] == ["-F", "pcPn"]            # field output only; no kill/repeat/write options
    assert not {"-r", "-k", "+r", "-a"} & set(lsof)
    assert runner.calls[1][:3] == [PS, "-o", "pid=,comm="]                  # read-only listing


def test_pids_are_passed_to_ps_in_bounded_chunks(monkeypatch):
    monkeypatch.setattr(macos, "_PS_CHUNK", 2)
    runner = FakeRunner()
    MacOSProcessSource(runner).snapshot(NOW)
    ps_calls = [c for c in runner.calls if c[0] == PS]
    assert len(ps_calls) == 2 and all(len(c[-1].split(",")) <= 2 for c in ps_calls)


def test_if_ps_fails_process_names_are_still_reported_without_application_names():
    snap = MacOSProcessSource(FakeRunner(ps_error=ProcessSourceError("ps failed"))).snapshot(NOW)
    assert snap.mappings and all(m.application is None for m in snap.mappings)
    assert any("Application names could not be read" in n for n in snap.notes)


def test_an_empty_socket_table_is_an_empty_snapshot_not_an_error():
    snap = MacOSProcessSource(FakeRunner(lsof="")).snapshot(NOW)
    assert snap.mappings == [] and snap.processes == 0


def test_lsof_failure_is_an_error_not_an_empty_answer():
    def boom(args):
        raise ProcessSourceError("lsof failed: permission denied")
    with pytest.raises(ProcessSourceError):
        MacOSProcessSource(boom).snapshot(NOW)


# ------------------------------------------------------------------ run_command: no shell, bounded, honest errors
def test_run_command_never_uses_a_shell_and_has_a_timeout(monkeypatch):
    seen = {}

    def fake_run(args, **kw):
        seen.update(kw, args=args)
        return subprocess.CompletedProcess(args, 0, stdout="out", stderr="")
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert run_command([LSOF, "-nP"]) == "out"
    assert seen["shell"] is False and seen["timeout"] == macos.TIMEOUT_SECONDS and seen["capture_output"] is True and seen["args"] == [LSOF, "-nP"]


def test_run_command_error_cases(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda a, **k: subprocess.CompletedProcess(a, 1, stdout="", stderr=""))
    assert run_command([LSOF]) == ""                                   # lsof exits 1 when nothing matches
    monkeypatch.setattr(subprocess, "run", lambda a, **k: subprocess.CompletedProcess(a, 2, stdout="", stderr="bad option"))
    with pytest.raises(ProcessSourceError, match="bad option"):
        run_command([LSOF])

    def timeout(a, **k):
        raise subprocess.TimeoutExpired(a, 1)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(ProcessSourceError, match="did not answer"):
        run_command([LSOF])

    def missing(a, **k):
        raise FileNotFoundError(a[0])
    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(ProcessSourceError, match="not available"):
        run_command([LSOF])


# ------------------------------------------------------------------ platform abstraction
def test_the_platform_factory_picks_macos_and_is_honest_elsewhere():
    assert isinstance(get_process_source("darwin"), MacOSProcessSource)
    for name, label in (("linux", "Linux"), ("win32", "Windows"), ("freebsd14", "freebsd14")):
        src = get_process_source(name)
        assert isinstance(src, UnsupportedProcessSource) and not src.supported and src.platform == label
        assert "not implemented" in src.permission_note
        with pytest.raises(ProcessSourceError, match="not supported"):
            src.snapshot(NOW)


def test_macos_permission_note_states_what_is_and_is_not_needed():
    note = MacOSProcessSource().permission_note
    assert "No administrator rights" in note and "Full Disk Access" in note and "your own user account" in note
    assert "Process information unavailable" in note
