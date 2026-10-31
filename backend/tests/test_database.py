from sqlalchemy import text

from app.database import make_engine


def test_sqlite_engine_works(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'sub' / 't.db'}")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT 1")).scalar() == 1
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
