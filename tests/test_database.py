from pathlib import Path

from app.storage.database import get_connection, initialize_database


def test_database_initialization(tmp_path: Path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    with get_connection(db_path) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            AND name = 'indicators'
            """
        ).fetchone()

    assert table is not None
