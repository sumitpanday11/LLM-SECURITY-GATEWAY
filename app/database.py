import os

import psycopg
from psycopg.rows import dict_row


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:1234@localhost:5432/llm_security_gateway",
)


def get_db_connection():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
    )