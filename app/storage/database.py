import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = Path("data/threat_intel.db")


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Create a connection to the SQLite database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Create the database tables if they do not already exist."""

    with get_connection(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                indicator_type TEXT NOT NULL,

                sources TEXT NOT NULL DEFAULT '[]',
                tags TEXT NOT NULL DEFAULT '[]',

                confidence INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT 'low',

                first_seen TEXT,
                last_seen TEXT,

                enrichment TEXT NOT NULL DEFAULT '{}',

                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(value, indicator_type)
            )
            """
        )

        connection.commit()
