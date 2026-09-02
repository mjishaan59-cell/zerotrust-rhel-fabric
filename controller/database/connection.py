import os

import psycopg
from psycopg.rows import dict_row


def get_database_connection():
    database_url = os.getenv(
        "ZTRF_DATABASE_URL",
        "postgresql://ztrf_app:ZTRF_DB_2026_CHANGE_ME@127.0.0.1:5432/ztrf",
    )

    return psycopg.connect(
        database_url,
        row_factory=dict_row,
    )
