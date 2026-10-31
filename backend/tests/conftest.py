# Having a conftest here puts `tests/` on sys.path so test modules can `import pcap_factory`.
from pathlib import Path

import pytest

import pcap_factory as pf
from app.analysis import analyze_pcap
from app.detection import DetectionConfig, detect_threats

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_pcap() -> Path:
    return FIXTURES / "sample.pcap"


@pytest.fixture
def make_pcap(tmp_path):
    def _make(packets, name="t.pcap", sort=True):
        """Write a capture; ``sort=False`` keeps the given order (file order != time order)."""
        return pf.write_pcap(tmp_path / name, sorted(packets, key=lambda p: p.time) if sort else list(packets))
    return _make


@pytest.fixture
def detect(make_pcap):
    """Write packets to a pcap, analyze it, run detection. Returns (findings, analysis_result)."""
    def _detect(packets, config: DetectionConfig | None = None):
        result = analyze_pcap(make_pcap(packets))
        return detect_threats(result, config), result
    return _detect


@pytest.fixture(autouse=True)
def history(tmp_path, monkeypatch):
    """Every test gets its own empty performance-history database; none ever touches the real local one."""
    from app.database import make_engine
    from app.migrations import migrate
    from app.services import performance_history as ph

    engine = make_engine(f"sqlite:///{tmp_path / 'history.db'}")
    migrate(engine)
    hist = ph.PerformanceHistory(engine)
    monkeypatch.setattr(ph, "_history", hist)
    return hist


@pytest.fixture(autouse=True)
def process_mapper(monkeypatch):
    """Tests never execute real lsof/ps: the app-wide mapper is an empty one with a source that refuses to run."""
    from app.models.process import ProcessSnapshot
    from app.platform.base import ProcessConnectionSource, ProcessSourceError
    from app.services import process_mapper as pm

    class NoOs(ProcessConnectionSource):
        platform, mechanism, permission_note = "test", "none", "test source"

        def snapshot(self, now: float) -> ProcessSnapshot:
            raise ProcessSourceError("the OS is not available in tests")

    mapper = pm.ProcessMapper(source=NoOs())
    monkeypatch.setattr(pm, "_mapper", mapper)
    return mapper


@pytest.fixture(autouse=True)
def capture_library(tmp_path, monkeypatch):
    """Tests get their own capture folder and library; none ever writes into the real captures/ directory."""
    from app.config import settings
    from app.database import make_engine
    from app.migrations import migrate
    from app.services import capture_store as cs

    monkeypatch.setattr(settings, "captures_dir", tmp_path / "captures")
    engine = make_engine(f"sqlite:///{tmp_path / 'captures.db'}")
    migrate(engine)
    store = cs.CaptureStore(engine, tmp_path / "captures")
    monkeypatch.setattr(cs, "_store", store)
    return store


@pytest.fixture(autouse=True)
def app_settings(tmp_path, monkeypatch):
    """Every test starts from default settings in its own database, with an in-memory keychain (never the real one)."""
    from app.database import make_engine
    from app.migrations import migrate
    from app.services import app_settings as svc
    from app.services import secret_store as ss

    engine = make_engine(f"sqlite:///{tmp_path / 'settings.db'}")
    migrate(engine)
    service = svc.SettingsService(engine)
    monkeypatch.setattr(svc, "_service", service)
    monkeypatch.setattr(ss, "_store", ss.MemorySecretStore())
    from app.services import ai_usage as au

    monkeypatch.setattr(au, "_usage", au.AiUsage(engine))
    return service
