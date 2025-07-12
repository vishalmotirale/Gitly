import sqlite3
import os
from flask import g  # ✅ This is essential

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "gitly.db")  # Absolute path: tracking/gitly.db

def get_db():
    if 'db' not in g:
        print("📦 Using DB at:", DB_PATH)  # Debug print
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db
def close_db(e=None):  # ✅ Add this back
    db = g.pop('db', None)
    if db is not None:
        db.close()