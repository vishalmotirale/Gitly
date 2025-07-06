import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash # Import flash for user messages
from dotenv import load_dotenv
from oauthlib.oauth2 import MismatchingStateError

# Load environment variables from repos.env (for local development)
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

# NEW FIX: Get the server-side PAT from environment variables using the CORRECT name
# This token will be used for unauthenticated (public) API requests
# It's crucial this is set on Render as an environment variable
github_pat = os.getenv('GITHUB_APP_TOKEN') # <--- CHANGED THIS LINE FROM "GITHUB_PAT" TO "GITHUB_APP_TOKEN"

# Base URL for GitHub API
GITHUB_API_BASE_URL = 'https://api.github.com'

# Ensure all necessary environment variables are set
if not all([app.secret_key, client_id, client_secret]):
    # Added github_pat to the check to ensure it's loaded for local dev, though Render handles it for deployment
    if not github_pat and os.getenv('RENDER'): # Only raise if not on Render and PAT is missing
        raise EnvironmentError("Missing required environment variables. Please check 'repos.env' for FLASK_SECRET_KEY, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and GITHUB_APP_TOKEN.")
    elif not os.getenv('RENDER') and not all([app.secret_key, client_id, client_secret]):
        raise EnvironmentError("Missing required environment variables. Please check 'repos.env' for FLASK_SECRET_KEY, GITHUB_CLIENT_ID, and GITHUB_CLIENT_SECRET.")


# --- Helper function to print rate limit info ---
def print_rate_limit_info(response, context=""):
    rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
    rate_limit_reset = response.headers.get('X-RateLimit-Reset')
    print(f"DEBUG: {context} Rate Limit Remaining: {rate_limit_remaining}, Reset: {rate_limit_reset}")


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
    # The 'repo' scope grants full control of private repositories for the authenticated user.
    # If you only need public repo access for logged-in users, you can change this to ["public_repo"]
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
                print(f"DEBUG: User API Status (Authenticated): {user_response.status_code}")
                print_rate_limit_info(user_response, "Authenticated User API")
                user_response.raise_for_status()
                user_data = user_response.json()

                page = 1
                while True:
                    repo_response = github.get(REPO_API, params={"per_page": 100, "page": page, "type": "all"})
                    print(f"DEBUG: Repo API Status (Authenticated, page {page}): {repo_response.status_code}")
                    print_rate_limit_info(repo_response, f"Authenticated Repo API (page {page})")
                    repo_response.raise_for_status()
                    data = repo_response.json()
                    if not data:
                        break
                    
                    for repo in data:
                        repo['private'] = bool(repo.get('private', False))
                    all_repos.extend(data)
                    page += 1
                
            else: # Logged-in user viewing ANOTHER user's profile (public repos only)
                # These requests are still authenticated by the logged-in user's token
                user_resp = github.get(f"{GITHUB_API_BASE_URL}/users/{username}")
                print(f"DEBUG: Other User API Status (Authenticated): {user_resp.status_code}")
                print_rate_limit_info(user_resp, "Authenticated Other User API")
                if user_resp.status_code != 200:
                    error_message = "User not found or an error occurred."
                else:
                    user_data = user_resp.json()
                    page = 1
                    while True:
                        r = github.get(f"{GITHUB_API_BASE_URL}/users/{username}/repos", params={"per_page": 100, "page": page})
                        print(f"DEBUG: Other User Repos API Status (Authenticated, page {page}): {r.status_code}")
                        print_rate_limit_info(r, f"Authenticated Other User Repos API (page {page})")
                        if r.status_code != 200:
                            error_message = f"Failed to fetch repositories for {username}. It might be a private user or an API error."
                            break
                        data = r.json()
                        if not data:
                            break
                        for repo in data:
                            repo['private'] = bool(repo.get('private', False))
                        all_repos.extend(data)
                        page += 1
                    
        except requests.exceptions.RequestException as e:
            print(f"ERROR: GitHub API request error (authenticated path): {e}")
            error_message = "Failed to communicate with GitHub API. Please check your internet connection or try again later."
            if e.response and e.response.status_code == 403:
                 error_message = "GitHub API rate limit exceeded for your account. Please wait or try again later."
        except Exception as e:
            print(f"ERROR: An unexpected error occurred in dashboard (authenticated path): {e}")
            error_message = "An unexpected error occurred. Please try again."

    # --- Unauthenticated User Logic (Now using PAT if available) ---
    else:
        if not username:
            return redirect(url_for('index'))

        # Prepare headers for PAT authentication if PAT is available
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if github_pat: # <--- NEW: Check if PAT exists (this will now be true if GITHUB_APP_TOKEN is set on Render)
            headers['Authorization'] = f"token {github_pat}" # <--- NEW: Add Authorization header

        # Fetch user profile using requests.get with PAT headers
        u_resp = requests.get(f"{GITHUB_API_BASE_URL}/users/{username}", headers=headers)
        print(f"DEBUG: Unauthenticated User API Status: {u_resp.status_code}")
        print_rate_limit_info(u_resp, "Unauthenticated User API")
        if u_resp.status_code != 200:
            error_message = "User not found."
            if u_resp.status_code == 403:
                error_message = "GitHub API rate limit exceeded for public searches. Please try again later or log in."
            # If user not found, no need to proceed to fetch repos
            return render_template('dashboard.html', user=user_data, repos=all_repos, error=error_message)
        else:
            user_data = u_resp.json()
            page = 1
            while True:
                # Fetch repositories using requests.get with PAT headers
                r_resp = requests.get(f"{GITHUB_API_BASE_URL}/users/{username}/repos", params={"per_page": 100, "page": page}, headers=headers)
                print(f"DEBUG: Unauthenticated Repo API Status (page {page}): {r_resp.status_code}")
                print_rate_limit_info(r_resp, f"Unauthenticated Repo API (page {page})")
                if r_resp.status_code != 200:
                    error_message = "Failed to fetch repositories."
                    if r_resp.status_code == 403:
                        error_message = "GitHub API rate limit exceeded for public searches. Please try again later or log in."
                    break
                data = r_resp.json()
                if not data:
                    break
                for repo in data:
                    repo['private'] = bool(repo.get('private', False))
                all_repos.extend(data)
                page += 1
            
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
    flash('You have been logged out.', 'info') # Added flash message
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
