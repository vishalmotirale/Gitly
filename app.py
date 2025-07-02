import os
from flask import Flask, redirect, url_for, session, render_template, request
from requests_oauthlib import OAuth2Session
import requests
from dotenv import load_dotenv
from oauthlib.oauth2 import MismatchingStateError

# Load environment variables from repos.env
load_dotenv('repos.env')

# IMPORTANT: This line is for local development with HTTP.
# For production, ensure HTTPS is used and remove this line or set to '0'.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
# Flask secret key for session management, loaded from environment variables
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# GitHub OAuth credentials
client_id = os.getenv("GITHUB_CLIENT_ID")
client_secret = os.getenv("GITHUB_CLIENT_SECRET")

# Ensure all necessary environment variables are set
if not all([app.secret_key, client_id, client_secret]):
    raise EnvironmentError("Missing required environment variables. Please check 'repos.env' for FLASK_SECRET_KEY, GITHUB_CLIENT_ID, and GITHUB_CLIENT_SECRET.")

# GitHub OAuth URLs
AUTH_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'
USER_API = 'https://api.github.com/user'
REPO_API = 'https://api.github.com/user/repos'

# --- Routes ---

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
    github = OAuth2Session(client_id, scope=["repo"]) # 'repo' scope includes private repos
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
    Handles both authenticated and unauthenticated scenarios. All filtering is now
    handled client-side by dashboard.html's JavaScript.
    """
    username = request.args.get('username')

    all_repos = []
    user_data = None
    error_message = None
    
    # --- Authenticated User Logic ---
    if 'oauth_token' in session:
        github = OAuth2Session(client_id, token=session['oauth_token'])

        try:
            if not username: # Logged-in user viewing their OWN repositories
                user_response = github.get(USER_API)
                user_response.raise_for_status()
                user_data = user_response.json()

                page = 1
                while True:
                    # For authenticated user, fetch all repos (public and private)
                    # The 'type' parameter can be used, but 'repo' scope should grant access to all.
                    # GitHub API typically returns all repos accessible by the token by default for /user/repos
                    repo_response = github.get(REPO_API, params={"per_page": 100, "page": page})
                    repo_response.raise_for_status()
                    data = repo_response.json()
                    if not data:
                        break
                    all_repos.extend(data)
                    page += 1
                
            else: # Logged-in user viewing ANOTHER user's profile (public repos only)
                user_resp = github.get(f"https://api.github.com/users/{username}")
                if user_resp.status_code != 200:
                    error_message = "User not found."
                else:
                    user_data = user_resp.json()
                    page = 1
                    while True:
                        r = github.get(f"https://api.github.com/users/{username}/repos", params={"per_page": 100, "page": page})
                        if r.status_code != 200:
                            error_message = f"Failed to fetch repositories for {username}. It might be a private user or rate limit exceeded."
                            break
                        data = r.json()
                        if not data:
                            break
                        all_repos.extend(data)
                        page += 1
                    
        except requests.exceptions.RequestException as e:
            print(f"GitHub API request error (authenticated path): {e}")
            error_message = "Failed to communicate with GitHub API. Please try again."
        except Exception as e:
            print(f"An unexpected error occurred in dashboard (authenticated path): {e}")
            error_message = "An unexpected error occurred. Please try again."

    # --- Unauthenticated User Logic ---
    else:
        if not username:
            return redirect(url_for('index'))

        u_resp = requests.get(f"https://api.github.com/users/{username}")
        if u_resp.status_code != 200:
            error_message = "User not found."
            if u_resp.status_code == 403:
                error_message = "GitHub API rate limit exceeded for public searches. Please try again later or log in."
        else:
            user_data = u_resp.json()
            page = 1
            while True:
                r_resp = requests.get(f"https://api.github.com/users/{username}/repos", params={"per_page": 100, "page": page})
                if r_resp.status_code != 200:
                    error_message = "Failed to fetch repositories."
                    if r_resp.status_code == 403:
                        error_message = "GitHub API rate limit exceeded for public searches. Please try again later or log in."
                    break
                data = r_resp.json()
                if not data:
                    break
                all_repos.extend(data)
                page += 1
            
    # The dashboard.html now handles filtering via JavaScript
    return render_template(
        'dashboard.html', 
        user=user_data, 
        repos=all_repos, 
        error=error_message
    )

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
