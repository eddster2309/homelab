"""Tiny ClickHouse HTTP client shared by the enricher jobs."""
from __future__ import annotations

import json
import os

import requests


class ClickHouse:
    def __init__(self):
        self.url = os.environ.get("CLICKHOUSE_URL", "http://clickhouse-netflow.netflow.svc:8123")
        self.s = requests.Session()
        self.s.headers.update({"X-ClickHouse-User": os.environ.get("CLICKHOUSE_USER", "enricher"),
                               "X-ClickHouse-Key": os.environ["CLICKHOUSE_PASSWORD"]})

    def q(self, sql: str, body: str | None = None, **settings) -> str:
        r = self.s.post(self.url, params={"query": sql, **settings}, data=(body or "").encode(), timeout=300)
        if r.status_code != 200:
            raise RuntimeError(f"ClickHouse: {sql[:100]}: {r.status_code} {r.text[:400]}")
        return r.text

    def scalar(self, sql: str) -> str:
        return self.q(sql + " FORMAT TSV").strip()

    def insert(self, table: str, rows: list[dict]) -> None:
        if rows:
            self.q(f"INSERT INTO {table} FORMAT JSONEachRow", "\n".join(json.dumps(r) for r in rows))

    def replace(self, table: str, rows: list[dict]) -> None:
        """Fill <table>_new and swap it in atomically."""
        self.q(f"TRUNCATE TABLE {table}_new")
        self.insert(f"{table}_new", rows)
        self.q(f"EXCHANGE TABLES {table} AND {table}_new")
