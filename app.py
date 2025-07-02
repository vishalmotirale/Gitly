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
    raise EnvironmentError("Missing required environment variables. Please check 'repos.env' for FLASK_SECRET_KEY, GITHUB_CLIENT_ID, and GITHUB_CLIENT_SECRET.")

AUTH_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'
USER_API = 'https://api.github.com/user'
REPO_API = 'https://api.github.com/user/repos'

def fetch_public_repos(username):
    """
    Fetches public repositories for a given username.
    Note: This function might hit GitHub API rate limits if not authenticated.
    """
    repos = []
    page = 1
    while True:
        res = requests.get(f"https://api.github.com/users/{username}/repos", params={"per_page": 100, "page": page})
        
        if res.status_code == 403:
            print("GitHub API rate limit exceeded for unauthenticated requests.")
            return {"error": "Rate limit exceeded. Please try again later or log in."}
        
        data = res.json()
        
        if res.status_code != 200 or not data:
            break
        
        repos.extend(data)
        page += 1
    return repos

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Handles the homepage, allowing users to search public repositories
    or initiate the GitHub OAuth login process.
    If already logged in, redirects to the dashboard.
    """
    if 'oauth_token' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if username:
            return redirect(url_for('dashboard', username=username))
    
    return render_template('index.html')

@app.route('/login')
def login():
    """
    Initiates the GitHub OAuth login flow.
    Redirects the user to GitHub's authorization page.
    """
    github = OAuth2Session(client_id, scope=["repo"])
    
    auth_url, state = github.authorization_url(AUTH_URL)
    session['oauth_state'] = state
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """
    Handles the callback from GitHub after user authorization.
    Exchanges the authorization code for an access token.
    """
    try:
        if 'oauth_state' not in session:
            print("OAuth state missing from session.")
            return redirect(url_for('index'))

        github = OAuth2Session(client_id, state=session['oauth_state'])
        
        token = github.fetch_token(
            TOKEN_URL,
            client_secret=client_secret,
            authorization_response=request.url 
        )
        session['oauth_token'] = token 
        
        return redirect(url_for('dashboard'))

    except MismatchingStateError:
        print("Mismatching state error during OAuth callback. Possible CSRF.")
        session.pop('oauth_state', None)
        return redirect(url_for('login'))
    except Exception as e:
        print(f"Error during OAuth callback: {e}")
        return redirect(url_for('index'))
    
@app.route('/dashboard')
def dashboard():
    """
    Displays the user's GitHub repositories or a specific user's public repositories.
    Handles both authenticated and unauthenticated scenarios.
    """
    username = request.args.get('username') 

    if 'oauth_token' in session:
        github = OAuth2Session(client_id, token=session['oauth_token'])

        try:
            if not username:
                user_response = github.get(USER_API)
                user_response.raise_for_status() 
                user = user_response.json()

                repos = []
                page = 1
                while True:
                    repo_response = github.get(REPO_API, params={"per_page": 100, "page": page})
                    repo_response.raise_for_status()
                    data = repo_response.json()
                    if not data: 
                        break
                    repos.extend(data)
                    page += 1
                return render_template('dashboard.html', user=user, repos=repos)

            else:
                user_resp = github.get(f"https://api.github.com/users/{username}")
                if user_resp.status_code != 200:
                    return render_template('dashboard.html', error="User not found.", repos=[], user=None)
                user = user_resp.json()

                repos = []
                page = 1
                while True:
                    r = github.get(f"https://api.github.com/users/{username}/repos", params={"per_page": 100, "page": page})
                    if r.status_code != 200:
                        print(f"Error fetching repos for {username}: {r.status_code} - {r.text}")
                        return render_template('dashboard.html', error=f"Failed to fetch repositories for {username}. It might be a private user or rate limit exceeded.", repos=[], user=None)
                    
                    data = r.json()
                    if not data: 
                        break
                    repos.extend(data)
                    page += 1
                return render_template('dashboard.html', user=user, repos=repos)

        except requests.exceptions.RequestException as e:
            print(f"GitHub API request error: {e}")
            return render_template('dashboard.html', error="Failed to communicate with GitHub API. Please try again.", repos=[], user=None)
        except Exception as e:
            print(f"An unexpected error occurred in dashboard (authenticated path): {e}")
            return render_template('dashboard.html', error="An unexpected error occurred. Please try again.", repos=[], user=None)

    if not username:
        return redirect(url_for('index'))

    u_resp = requests.get(f"https://api.github.com/users/{username}")
    if u_resp.status_code != 200:
        error_message = "User not found."
        if u_resp.status_code == 403:
            error_message = "GitHub API rate limit exceeded for public searches. Please try again later or log in."
        print(f"Error fetching user {username} (unauthenticated): {u_resp.status_code} - {u_resp.text}")
        return render_template('dashboard.html', error=error_message, repos=[], user=None)

    user = u_resp.json()
    repos = []
    page = 1
    while True:
        r_resp = requests.get(f"https://api.github.com/users/{username}/repos", params={"per_page": 100, "page": page})
        if r_resp.status_code != 200:
            print(f"Error fetching repos for {username} (unauthenticated): {r_resp.status_code} - {r_resp.text}")
            error_message = "Failed to fetch repositories."
            if r_resp.status_code == 403:
                error_message = "GitHub API rate limit exceeded for public searches. Please try again later or log in."
            return render_template('dashboard.html', error=error_message, repos=[], user=None)

        data = r_resp.json()
        if not data:
            break
        repos.extend(data)
        page += 1

    return render_template('dashboard.html', user=user, repos=repos)

@app.route('/logout')
def logout(): 
    """
    Logs out the user by clearing the session.
    """
    session.clear() 
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e): 
    """
    Custom error handler for 404 Not Found errors.
    """
    return render_template("404.html"), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 1000))
    app.run(host="0.0.0.0", port=port, debug=True)
