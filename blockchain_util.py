import hashlib
import json
import sqlite3
import time
import os

DB_FILE = "blockchain.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS blocks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT,
                  data TEXT,
                  prev_hash TEXT,
                  hash TEXT,
                  timestamp REAL)''')
    conn.commit()
    conn.close()

def get_last_block():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM blocks ORDER BY id DESC LIMIT 1")
    block = c.fetchone()
    conn.close()
    return block

def compute_hash(data, prev_hash, timestamp):
    record_str = f"{data}{prev_hash}{timestamp}"
    return hashlib.sha256(record_str.encode()).hexdigest()


def add_block(record: dict):
    """Add a new block only if the existing blockchain is valid."""

    init_db()

    # Verify the existing blockchain first
    is_valid, message = verify_chain()

    if not is_valid:
        raise ValueError(
            f"Cannot add block. Blockchain integrity check failed: {message}"
        )

    if "url" not in record:
        raise ValueError("Record must contain a URL.")

    conn = sqlite3.connect(DB_FILE)

    try:
        c = conn.cursor()

        # Get the latest block
        c.execute(
            "SELECT hash FROM blocks ORDER BY id DESC LIMIT 1"
        )
        last_block = c.fetchone()

        prev_hash = last_block[0] if last_block else "0"

        timestamp = time.time()
        data_json = json.dumps(record)

        block_hash = compute_hash(
            data_json,
            prev_hash,
            timestamp
        )

        c.execute(
            """INSERT INTO blocks
               (url, data, prev_hash, hash, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (
                record["url"],
                data_json,
                prev_hash,
                block_hash,
                timestamp
            )
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

def get_record(url: str):
    """Retrieve last record for a given URL"""
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT data FROM blocks WHERE url = ? ORDER BY id DESC LIMIT 1", (url,))
    row = c.fetchone()
    conn.close()

    if row:
        return json.loads(row[0])  # convert JSON string back to dict
    return None

def verify_chain():
    """Verify the integrity of all blocks in the blockchain."""
    init_db()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute(
        "SELECT id, data, prev_hash, hash, timestamp "
        "FROM blocks ORDER BY id ASC"
    )

    blocks = c.fetchall()
    conn.close()

    expected_prev_hash = "0"

    for block in blocks:
        block_id, data, prev_hash, stored_hash, timestamp = block

        # Check whether the previous hash matches
        if prev_hash != expected_prev_hash:
            return False, f"Chain broken at block {block_id}: previous hash mismatch."

        # Recalculate the block hash
        calculated_hash = compute_hash(data, prev_hash, timestamp)

        if calculated_hash != stored_hash:
            return False, f"Block {block_id} has been modified."

        expected_prev_hash = stored_hash

    return True, "Blockchain integrity verified successfully."