import os
from flask import Flask, redirect, url_for, session, render_template, request
from requests_oauthlib import OAuth2Session
import requests
from dotenv import load_dotenv
from oauthlib.oauth2 import MismatchingStateError


load_dotenv('repos.env')
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

client_id = os.getenv("GITHUB_CLIENT_ID")
client_secret = os.getenv("GITHUB_CLIENT_SECRET")

if not all([app.secret_key, client_id, client_secret]):
    raise EnvironmentError("Missing required environment variables in repos.env")

AUTH_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'
USER_API = 'https://api.github.com/user'
REPO_API = 'https://api.github.com/user/repos'

def fetch_public_repos(username):
    repos, page = [], 1
    while True:
        res = requests.get(f"https://api.github.com/users/{username}/repos", params={"per_page": 100, "page": page})
        if res.status_code == 403:
            return {"error": "Rate limit exceeded"}
        data = res.json()
        if res.status_code != 200 or not data:
            break
        repos += data
        page += 1
    return repos

@app.route('/', methods=['GET', 'POST'])
def index():
    # If already logged in, skip search and go to dashboard
    if 'oauth_token' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if username:
            return redirect(url_for('dashboard', username=username))
    return render_template('index.html')

@app.route('/login')
def login():
    github = OAuth2Session(client_id, scope=["repo"])
    auth_url, state = github.authorization_url(AUTH_URL)
    session['oauth_state'] = state
    return redirect(auth_url)

@app.route('/callback')
def callback():
    try:
        if 'oauth_state' not in session:
            return redirect(url_for('index'))

        github = OAuth2Session(client_id, state=session['oauth_state'])
        session['oauth_token'] = github.fetch_token(
            TOKEN_URL,
            client_secret=client_secret,
            authorization_response=request.url
        )
        return redirect(url_for('dashboard'))

    except MismatchingStateError:
        session.pop('oauth_state', None)
        return redirect(url_for('login'))
    
@app.route('/dashboard')
def dashboard():
    username = request.args.get('username')

    if 'oauth_token' in session:
        # Use OAuth token for all authenticated requests
        github = OAuth2Session(client_id, token=session['oauth_token'])

        try:
            # Case 1: No username param – show logged-in user's private + public repos
            if not username:
                user = github.get(USER_API).json()
                repos, page = [], 1
                while True:
                    r = github.get(REPO_API, params={"per_page": 100, "page": page})
                    data = r.json()
                    if r.status_code != 200 or not data: break
                    repos += data
                    page += 1
                return render_template('dashboard.html', user=user, repos=repos)

            # Case 2: Logged-in user viewing another profile (authenticated)
            user_resp = github.get(f"https://api.github.com/users/{username}")
            if user_resp.status_code != 200:
                return render_template('dashboard.html', error="User not found.", repos=[], user=None)
            user = user_resp.json()

            repos, page = [], 1
            while True:
                r = github.get(f"https://api.github.com/users/{username}/repos", params={"per_page": 100, "page": page})
                data = r.json()
                if r.status_code != 200 or not data: break
                repos += data
                page += 1

            return render_template('dashboard.html', user=user, repos=repos)

        except Exception as e:
            print(f"GitHub API error: {e}")
            return render_template('dashboard.html', error="Failed to fetch repositories.", repos=[], user=None)

    # If user not logged in – fallback to unauthenticated (subject to rate limit)
    if not username:
        return redirect(url_for('index'))

    u = requests.get(f"https://api.github.com/users/{username}")
    if u.status_code != 200:
        return render_template('dashboard.html', error="User not found or rate limit exceeded.", repos=[], user=None)

    user = u.json()
    repos, page = [], 1
    while True:
        r = requests.get(f"https://api.github.com/users/{username}/repos", params={"per_page": 100, "page": page})
        data = r.json()
        if r.status_code != 200 or not data: break
        repos += data
        page += 1

    return render_template('dashboard.html', user=user, repos=repos)
@app.route('/logout')
def logout(): 
    session.clear()
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e): return render_template("404.html"), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 1000))
    app.run(host="0.0.0.0", port=port)