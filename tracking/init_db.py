import sqlite3

def init_db():
    conn = sqlite3.connect("tracking/gitly.db")
    with open("tracking/schema.sql") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
