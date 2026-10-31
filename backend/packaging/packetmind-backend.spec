# PyInstaller spec for the packaged backend (one-folder build; faster to start than one-file, which unpacks on every launch).
# Build with:  cd backend && .venv/bin/pyinstaller --noconfirm --clean packaging/packetmind-backend.spec
from PyInstaller.utils.hooks import collect_all, collect_submodules

hidden = collect_submodules("app") + collect_submodules("uvicorn") + collect_submodules("scapy.layers") + [
    "scapy.layers.all", "keyring.backends.macOS", "keyring.backends.fail", "sqlalchemy.dialects.sqlite",
]
datas, binaries = [], []
for pkg in ("google.genai", "certifi"):  # the Gemini SDK ships data files and needs the CA bundle for HTTPS
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hidden += h

a = Analysis(
    ["../main.py"], pathex=[".."], binaries=binaries, datas=datas, hiddenimports=hidden, noarchive=False,
    # Development/test-only or unused packages: pyshark/tshark are not used by the app.
    excludes=["pytest", "pyshark", "tkinter", "matplotlib", "IPython", "PyInstaller", "setuptools", "pip", "anthropic"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="packetmind-backend", console=True, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, name="packetmind-backend", upx=False)
