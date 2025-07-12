from flask import request, session
from datetime import datetime
import json
from .db import get_db

def log_activity():
    db = get_db()
    username = session.get("github_user", {}).get("login", "anonymous")
    path = request.path
    params = dict(request.args)
    user_agent = request.headers.get("User-Agent", "unknown")
    ip_address = request.remote_addr or "unknown"
    timestamp = datetime.now()

    db.execute("""
        INSERT INTO user_activity (username, path, params, user_agent, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (username, path, json.dumps(params), user_agent, ip_address, timestamp))
    db.commit()
