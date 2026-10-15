"""Cross-process durable spool. Only a decoy and its paired agent share this volume."""
import json
import sqlite3
import time
from pathlib import Path


class DurableBuffer:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (uid TEXT PRIMARY KEY, body TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, body TEXT NOT NULL);
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def put(self, event: dict, limit: int = 50000):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM events").fetchone()[0] >= limit:
                raise BufferError("Очередь телеметрии заполнена; новые взаимодействия отклоняются")
            db.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?)",
                       (event["event_uid"], json.dumps(event), time.time()))

    def batch(self, limit=100):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT body FROM events ORDER BY created, uid LIMIT ?", (limit,))]

    def acknowledge(self, identifiers):
        with self.connect() as db:
            db.executemany("DELETE FROM events WHERE uid = ?", [(uid,) for uid in identifiers])

    def size(self):
        with self.connect() as db:
            return db.execute("SELECT count(*) FROM events").fetchone()[0]

    def set(self, key, value):
        with self.connect() as db:
            db.execute("INSERT INTO state VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET body=excluded.body", (key, json.dumps(value)))

    def get(self, key, default=None):
        with self.connect() as db:
            row = db.execute("SELECT body FROM state WHERE key = ?", (key,)).fetchone()
            return json.loads(row[0]) if row else default
