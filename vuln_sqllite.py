# vuln_sqlite_injection.py
# Bandit may flag SQL injection risks (B608-style)
import sqlite3
import sys

DB = "test_users.db"

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect(DB)
    # intentionally vulnerable: string formatting of SQL query
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    cur = conn.execute(query)
    row = cur.fetchone()
    conn.close()
    return row

if __name__ == "__main__":
    init_db()
    if len(sys.argv) != 2:
        print("Usage: python vuln_sqlite_injection.py <username>")
        sys.exit(1)
    print(get_user(sys.argv[1]))