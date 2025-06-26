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
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if username:
            return redirect(url_for('dashboard', username=username))
    return render_template('index.html')

@app.route('/login')
def login():
    github = OAuth2Session(client_id, scope="repo")
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
            TOKEN_URL, client_secret=client_secret, authorization_response=request.url
        )
        return redirect(url_for('dashboard'))
    except MismatchingStateError:
        session.pop('oauth_state', None)
        return redirect(url_for('login'))
    
@app.route('/dashboard')
def dashboard():
    if 'oauth_token' in session:
        github = OAuth2Session(client_id, token=session['oauth_token'])
        return render_template('dashboard.html', user=github.get(USER_API).json(), repos=github.get(REPO_API).json())
    
    username = request.args.get('username')
    if not username: return redirect(url_for('index'))
    u = requests.get(f"https://api.github.com/users/{username}")
    if u.status_code == 403: return render_template('dashboard.html', error="Rate limit exceeded", repos=[], user=None)
    if u.status_code != 200: return render_template('dashboard.html', error="User not found", repos=[], user=None)
    
    repos = fetch_public_repos(username)
    if isinstance(repos, dict): return render_template('dashboard.html', error=repos['error'], repos=[], user=u.json())
    return render_template('dashboard.html', user=u.json(), repos=repos)

@app.route('/logout')
def logout(): 
    session.clear()
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e): return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(debug=True)
