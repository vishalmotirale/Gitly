import os
import requests
from requests_oauthlib.oauth2_session import OAuth2Session 
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from dotenv import load_dotenv
from oauthlib.oauth2 import MismatchingStateError
import time
import sqlite3
import json
from datetime import datetime, timedelta

# Load environment variables from repos.env
load_dotenv('repos.env')

# Note: This line should only be used for local development over HTTP.
# Do not use this in production.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# --- Application Setup ---
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

client_id = os.getenv("GITHUB_CLIENT_ID")
client_secret = os.getenv("GITHUB_CLIENT_SECRET")

github_pat = os.getenv('GITHUB_APP_TOKEN')

GITHUB_API_BASE_URL = 'https://api.github.com'
AUTH_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'
REPO_PAGE_SIZE = 100

# Dictionary of language colors to be used throughout the app
LANGUAGE_COLORS = {
    "Python": "#3572A5",
    "JavaScript": "#F7DF1E",
    "HTML": "#E34C26",
    "CSS": "#563D7C",
    "Java": "#B07219",
    "C++": "#f34b7d",
    "C": "#555555",
    "Shell": "#89e051",
    "Go": "#00ADD8",
    "TypeScript": "#007ACC",
    "Ruby": "#CC342D",
    "PHP": "#787CB5",
    "Jupyter Notebook": "#FF6C00",
    "Swift": "#F05138",
    "Kotlin": "#7F52FF",
    "Rust": "#DEA584",
    "Dart": "#00B4AB",
    "Vue": "#41B883",
    "SCSS": "#C6538C",
    "Less": "#1D365D",
    "Perl": "#0298c3",
    "R": "#276DC3",
    "Matlab": "#E16737",
    "Objective-C": "#438eff",
    "Assembly": "#6E4C13",
    "Vim Script": "#199f4b",
    "Elixir": "#6E4A7E",
    "Erlang": "#B8399A",
    "Haskell": "#5E5086",
    "Lua": "#2C2D72",
    "Scala": "#DC322F",
    "C#": "#178600",
}

# --- Environment Variable Checks ---
if not app.secret_key:
    raise EnvironmentError("Missing FLASK_SECRET_KEY environment variable.")
if not client_id:
    raise EnvironmentError("Missing GITHUB_CLIENT_ID environment variable.")
if not client_secret:
    raise EnvironmentError("Missing GITHUB_CLIENT_SECRET environment variable.")
if not github_pat and not os.getenv('RENDER'):
    print("WARNING: GITHUB_APP_TOKEN not set. Public API requests might hit lower rate limits.")

# --- Database Connection and Setup ---
DATABASE = 'gitly.db'

def get_db():
    """
    Connects to the specified database file.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """
    Closes the database connection at the end of the request.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """
    Initializes the database from the gitly_schema.sql file.
    """
    with app.app_context():
        db = get_db()
        # This will create tables from the schema file.
        with open('gitly_schema.sql', 'r') as f:
            db.executescript(f.read())
        print("Database initialized from gitly_schema.sql")


# --- Helper Functions ---

def print_rate_limit_info(response, context=""):
    """Prints GitHub API rate limit information from response headers."""
    rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
    rate_limit_reset = response.headers.get('X-RateLimit-Reset')
    print(f"DEBUG: {context} Rate Limit Remaining: {rate_limit_remaining}, Reset: {rate_limit_reset}")

repo_language_cache = {}
CACHE_EXPIRY_SECONDS = 3600

def get_language_percentages(repo_full_name, headers):
    """
    Fetches language distribution for a repository from GitHub API, with caching.
    Args:
        repo_full_name (str): Full name of the repository (e.g., 'owner/repo').
        headers (dict): Dictionary of headers including Authorization token.
    Returns:
        dict: Language percentages (e.g., {'Python': 70.5, 'JavaScript': 29.5}).
    """
    cache_key = f"lang_data_{repo_full_name}"
    
    # Check cache first
    if cache_key in repo_language_cache and \
       (time.time() - repo_language_cache[cache_key]['timestamp']) < CACHE_EXPIRY_SECONDS:
        print(f"DEBUG: Using cached language data for {repo_full_name}")
        return repo_language_cache[cache_key]['data']

    url = f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/languages"
    resp = requests.get(url, headers=headers)
    print_rate_limit_info(resp, f"Languages API for {repo_full_name}")
    
    if resp.status_code == 403:
        print(f"ERROR: Rate limit hit for language data of {repo_full_name}. Response: {resp.text}")
        flash("GitHub API rate limit exceeded for language data. Some language bars may be missing.", 'error')
        return {}
    elif resp.status_code != 200:
        print(f"ERROR: Failed to fetch languages for {repo_full_name}. Status: {resp.status_code}, Response: {resp.text}")
        return {}
    
    data = resp.json()
    total = sum(data.values())
    if total == 0:
        percentages = {}
    else:
        percentages = {lang: round((count / total) * 100, 1) for lang, count in data.items()}
    
    # Store in cache
    repo_language_cache[cache_key] = {'data': percentages, 'timestamp': time.time()}
    
    return percentages

def calculate_overall_language_stats(all_repos, headers):
    """
    Aggregates language bytes from all repositories to calculate an overall
    language distribution for the user's entire profile.
    """
    total_language_bytes = {}
    for repo in all_repos:
        repo_languages_url = repo.get('languages_url')
        if repo_languages_url:
            try:
                lang_response = requests.get(repo_languages_url, headers=headers)
                lang_response.raise_for_status()
                repo_languages = lang_response.json()
                for lang, bytes in repo_languages.items():
                    total_language_bytes[lang] = total_language_bytes.get(lang, 0) + bytes
            except requests.exceptions.RequestException as e:
                # Log the error but continue to process other repositories
                print(f"Error fetching languages for overall stats for repo {repo['name']}: {e}")
    
    total_bytes = sum(total_language_bytes.values())
    if total_bytes == 0:
        return {}

    overall_percentages = {
        lang: (bytes / total_bytes) * 100
        for lang, bytes in total_language_bytes.items()
    }

    # Sort languages by percentage in descending order
    sorted_percentages = sorted(overall_percentages.items(), key=lambda item: item[1], reverse=True)
    return dict(sorted_percentages)

def get_project_activity_status(last_pushed_at):
    """
    Analyzes the last commit date and returns a human-readable status.
    Args:
        last_pushed_at (str): The 'pushed_at' timestamp string from the GitHub API.
    Returns:
        str: A string indicating the project's recent activity.
    """
    if not last_pushed_at:
        return "No commits yet"
    
    last_pushed_date = datetime.strptime(last_pushed_at, '%Y-%m-%dT%H:%M:%SZ')
    time_difference = datetime.utcnow() - last_pushed_date
    
    if time_difference < timedelta(weeks=1):
        return "Frequent commits"
    elif time_difference < timedelta(days=180): # Approx 6 months
        return "Recent activity"
    else:
        return "Low recent activity"

# --- API Endpoints for Database Interaction ---

@app.route('/api/log_activity', methods=['POST'])
def log_activity_api():
    """
    API endpoint to log user activity.
    Expects a JSON payload with 'username', 'ip_address', 'user_agent', and 'path'.
    """
    data = request.json
    username = data.get('username')
    ip_address = data.get('ip_address')
    user_agent = data.get('user_agent')
    path = data.get('path')

    # Basic input validation
    if not all([username, ip_address, user_agent, path]):
        return jsonify({'error': 'Missing required fields in request payload'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO activity_logs (username, ip_address, user_agent, path) VALUES (?, ?, ?, ?)",
        (username, ip_address, user_agent, path)
    )
    db.commit()
    return jsonify({'message': 'Activity logged successfully'}), 201

@app.route('/api/ai_insights', methods=['POST'])
def save_ai_insight():
    """
    API endpoint to save a new AI-generated insight.
    Expects a JSON payload with 'username', 'repo_name', and 'insight'.
    """
    data = request.json
    username = data.get('username')
    repo_name = data.get('repo_name')
    insight = data.get('insight')

    # Basic input validation
    if not all([username, repo_name, insight]):
        return jsonify({'error': 'Missing required fields in request payload'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO ai_insights (username, repo_name, insight) VALUES (?, ?, ?)",
        (username, repo_name, insight)
    )
    db.commit()
    return jsonify({'message': 'AI insight saved successfully'}), 201


@app.route('/api/ai_insights/<username>/<repo_name>', methods=['GET'])
def get_ai_insights(username, repo_name):
    """
    API endpoint to retrieve AI insights for a user.
    If repo_name == 'all', fetch all insights for that user.
    """
    db = get_db()
    cursor = db.cursor()

    if repo_name == "all":
        cursor.execute(
            "SELECT insight, created_at FROM ai_insights WHERE username = ?",
            (username,)
        )
    else:
        cursor.execute(
            "SELECT insight, created_at FROM ai_insights WHERE username = ? AND repo_name = ?",
            (username, repo_name)
        )

    insights = cursor.fetchall()
    if not insights:
        return jsonify({'message': 'No insights found'}), 404

    insights_list = [dict(insight) for insight in insights]
    return jsonify(insights_list), 200

    if not insights:
        return jsonify({'message': 'No insights found for this repository'}), 404

    # Convert the list of Row objects to a list of dictionaries for JSON serialization
    insights_list = [dict(insight) for insight in insights]
    return jsonify(insights_list), 200

@app.route('/api/cached_repos/<user_id>/<repo_full_name>', methods=['GET'])
def get_cached_repo(user_id, repo_full_name):
    """
    Retrieves cached repository data for a given user and repository from the 'cached_repos' table.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT repo_data, last_updated FROM cached_repos WHERE user_id = ? AND repo_full_name = ?",
        (user_id, repo_full_name,)
    )
    repo_row = cursor.fetchone()

    if not repo_row:
        return jsonify({'message': 'Repository not found in cache'}), 404

    # The repo_data is stored as a JSON string, so we need to parse it back into an object
    repo_data = json.loads(repo_row['repo_data'])
    last_updated = repo_row['last_updated']
    return jsonify({'repo_data': repo_data, 'last_updated': last_updated}), 200


# --- Flask Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'oauth_token' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if username:
            return redirect(url_for('dashboard', username=username))
    
    return render_template('index.html')

@app.route('/login')
def login():
    github = OAuth2Session(client_id, scope=["repo", "read:user"])
    auth_url, state = github.authorization_url(AUTH_URL)
    session['oauth_state'] = state
    return redirect(auth_url)

@app.route('/callback')
def callback():
    try:
        if 'oauth_state' not in session:
            print("OAuth state missing from session.")
            flash("Authentication failed. Please try logging in again.", 'error')
            return redirect(url_for('index'))

        github = OAuth2Session(client_id, state=session['oauth_state'])
        token = github.fetch_token(
            TOKEN_URL,
            client_secret=client_secret,
            authorization_response=request.url
        )
        session['oauth_token'] = token
        flash('Successfully logged in with GitHub!', 'success')
        return redirect(url_for('dashboard'))

    except MismatchingStateError:
        print("Mismatching state error during OAuth callback. Possible CSRF.")
        flash("Authentication failed due to security mismatch. Please try logging in again.", 'error')
        session.pop('oauth_state', None)
        return redirect(url_for('login'))
    except Exception as e:
        print(f"Error during OAuth callback: {e}")
        flash(f"An error occurred during login: {e}", 'error')
        return redirect(url_for('index'))
    
@app.route('/dashboard')
def dashboard():
    username = request.args.get('username')
    all_repos = []
    user_data = None
    error_message = None
    is_authenticated = 'oauth_token' in session
    
    request_headers = {'Accept': 'application/vnd.github.v3+json'}
    
    # Determine which token to use
    token_to_use = None
    if is_authenticated:
        token_to_use = session['oauth_token']['access_token']
        print("DEBUG: Dashboard using user's OAuth token.")
    elif github_pat:
        token_to_use = github_pat
        print("DEBUG: Dashboard using server-side GITHUB_APP_TOKEN.")
    else:
        print("WARNING: No authentication token available for dashboard requests.")
        if not username:
            flash("Please log in or search for a public user.", "info")
            return redirect(url_for('index'))
            
    if token_to_use:
        request_headers['Authorization'] = f"token {token_to_use}"

    # --- Log activity when dashboard is accessed ---
    if username or is_authenticated:
        try:
            log_data = {
                'username': username if username else "authenticated_user",
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'path': request.path
            }
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO activity_logs (username, ip_address, user_agent, path) VALUES (?, ?, ?, ?)",
                (log_data['username'], log_data['ip_address'], log_data['user_agent'], log_data['path'])
            )
            db.commit()
            print("DEBUG: Logged dashboard visit successfully.")
        except Exception as e:
            print(f"ERROR: Failed to log activity: {e}")

    try:
        # Fetch user data and repos based on whether a username is provided
        if not username: # Authenticated user viewing their own repos
            user_response = requests.get(f"{GITHUB_API_BASE_URL}/user", headers=request_headers)
            user_response.raise_for_status()
            user_data = user_response.json()
            repos_url = f"{GITHUB_API_BASE_URL}/user/repos"
        else: # Viewing a public user's repos
            user_response = requests.get(f"{GITHUB_API_BASE_URL}/users/{username}", headers=request_headers)
            user_response.raise_for_status()
            user_data = user_response.json()
            repos_url = f"{GITHUB_API_BASE_URL}/users/{username}/repos"

        # Fetch all repositories, handling pagination
        page = 1
        while True:
            repo_response = requests.get(repos_url, params={"per_page": REPO_PAGE_SIZE, "page": page, "type": "all"}, headers=request_headers)
            print_rate_limit_info(repo_response, f"Repo API (page {page})")
            repo_response.raise_for_status()
            data = repo_response.json()
            if not data:
                break
            
            for repo in data:
                repo['private'] = bool(repo.get('private', False))
                # Call get_language_percentages for each repo for individual bars
                repo['language_percentages'] = get_language_percentages(repo['full_name'], request_headers)
                
                # --- Determine and add the project activity status ---
                last_pushed_at = repo.get('pushed_at')
                repo['activity_status'] = get_project_activity_status(last_pushed_at)
            
            all_repos.extend(data)
            page += 1
        
        user_data['total_repos'] = len(all_repos)

    except requests.exceptions.RequestException as e:
        print(f"ERROR: GitHub API request error: {e}")
        error_message = "Failed to communicate with GitHub API. Please try again later."
        if e.response and e.response.status_code == 404:
            error_message = f"GitHub user '{username}' not found."
        elif e.response and e.response.status_code == 403:
            error_message = "GitHub API rate limit exceeded. Please try again later or log in."
        if is_authenticated:
            session.pop('oauth_token', None) # Clear token on auth error
        
    # Calculate overall language statistics for the profile
    overall_language_stats = {}
    if all_repos:
        overall_language_stats = calculate_overall_language_stats(all_repos, request_headers)

    return render_template(
        'dashboard.html',
        user=user_data,
        repos=all_repos,
        error=error_message,
        is_authenticated=is_authenticated,
        language_colors=LANGUAGE_COLORS,
        overall_language_stats=overall_language_stats
    )

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 1000))
    app.run(host="0.0.0.0", port=port, debug=True)
