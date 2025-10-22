import sqlite3

DB_NAME = "results.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            subdomain TEXT,
            ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_result(domain, subdomain, ip):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO results (domain, subdomain, ip)
        VALUES (?, ?, ?)
    """, (domain, subdomain, ip))
    conn.commit()
    conn.close()
