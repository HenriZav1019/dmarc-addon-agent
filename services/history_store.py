import sqlite3
from datetime import datetime

DB_PATH = "scan_history.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domain_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            domain TEXT NOT NULL,
            dmarc_status TEXT,
            spf_status TEXT,
            health_score INTEGER,
            health_label TEXT,
            summary TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sender_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_value TEXT NOT NULL,
            sender_type TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def save_domain_scan(domain: str, result: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dmarc_status = result.get("dmarc", {}).get("status", "unknown")
    spf_status = result.get("spf", {}).get("status", "unknown")
    health_score = result.get("health", {}).get("score", 0)
    health_label = result.get("health", {}).get("label", "Unknown")
    summary = " | ".join(result.get("summary", []))

    cursor.execute("""
        INSERT INTO domain_scans (
            scanned_at,
            domain,
            dmarc_status,
            spf_status,
            health_score,
            health_label,
            summary
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        scanned_at,
        domain,
        dmarc_status,
        spf_status,
        health_score,
        health_label,
        summary
    ))

    conn.commit()
    conn.close()


def get_recent_domain_scans(limit: int = 10):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT scanned_at, domain, dmarc_status, spf_status, health_score, health_label, summary
        FROM domain_scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    return rows


def get_all_domain_scans():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT scanned_at, domain, dmarc_status, spf_status, health_score, health_label, summary
        FROM domain_scans
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows

def upsert_sender_observation(sender_value: str, sender_type: str):
    if not sender_value:
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT id, first_seen, last_seen
        FROM sender_inventory
        WHERE sender_value = ? AND sender_type = ?
    """, (sender_value, sender_type))

    row = cursor.fetchone()

    if row:
        cursor.execute("""
            UPDATE sender_inventory
            SET last_seen = ?
            WHERE id = ?
        """, (now, row[0]))
        is_new = False
    else:
        cursor.execute("""
            INSERT INTO sender_inventory (sender_value, sender_type, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
        """, (sender_value, sender_type, now, now))
        is_new = True

    conn.commit()
    conn.close()

    return is_new

def save_header_sender_mapping(sender_mapping: dict):
    results = {}

    mapping = {
        "from_domain": sender_mapping.get("from_domain", ""),
        "return_path_domain": sender_mapping.get("return_path_domain", ""),
        "reply_to_domain": sender_mapping.get("reply_to_domain", ""),
        "dkim_domain": sender_mapping.get("dkim_domain", ""),
        "dkim_selector": sender_mapping.get("dkim_selector", ""),
        "spf_mailfrom_domain": sender_mapping.get("spf_mailfrom_domain", ""),
    }

    for sender_type, sender_value in mapping.items():
        if sender_value:
            results[sender_type] = upsert_sender_observation(sender_value, sender_type)

    return results


def get_all_sender_inventory():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sender_value, sender_type, first_seen, last_seen
        FROM sender_inventory
        ORDER BY last_seen DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows

def sender_exists(sender_value: str, sender_type: str):
    if not sender_value:
        return False

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 1
        FROM sender_inventory
        WHERE sender_value = ? AND sender_type = ?
        LIMIT 1
    """, (sender_value, sender_type))

    row = cursor.fetchone()
    conn.close()

    return row is not None