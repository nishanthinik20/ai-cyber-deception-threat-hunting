import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join("data", "security_events.db")


def init_db():
    os.makedirs("data", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source TEXT,
            description TEXT,
            severity TEXT,
            status TEXT DEFAULT 'New'
        )
    """)

    conn.commit()
    conn.close()


def add_event(event_type, source, description, severity):
    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (timestamp, event_type, source, description, severity)
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event_type,
        source,
        description,
        severity
    ))

    conn.commit()
    conn.close()


def get_recent_events(limit=20):
    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, timestamp, event_type, source,
               description, severity, status
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    events = cursor.fetchall()

    conn.close()

    return events


if __name__ == "__main__":
    init_db()

    add_event(
        "SYSTEM_TEST",
        "127.0.0.1",
        "Cyber deception database initialized successfully",
        "LOW"
    )

    print("Database initialized successfully!")