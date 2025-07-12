import sqlite3
from flask import g

def get_db():
    if 'db' not in g:
        import os
        print("📦 Using DB path:", os.path.abspath("tracking/gitly.db"))
        g.db = sqlite3.connect("tracking/gitly.db")
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()
