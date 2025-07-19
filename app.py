import os
import requests
from requests_oauthlib.oauth2_session import OAuth2Session 
from flask import Flask, render_template, request, redirect, url_for, session, flash # Ensure flash is imported
from dotenv import load_dotenv
from oauthlib.oauth2 import MismatchingStateError
import datetime
import time

# Load environment variables from repos.env
load_dotenv('repos.env')

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

client_id = os.getenv("GITHUB_CLIENT_ID")
client_secret = os.getenv("GITHUB_CLIENT_SECRET")

github_pat = os.getenv('GITHUB_APP_TOKEN') # Correctly looking for GITHUB_APP_TOKEN

GITHUB_API_BASE_URL = 'https://api.github.com'
AUTH_URL = 'https://github.com/login/oauth/authorize'

if not app.secret_key:
    raise EnvironmentError("Missing FLASK_SECRET_KEY environment variable.")
if not client_id:
    raise EnvironmentError("Missing GITHUB_CLIENT_ID environment variable.")
if not client_secret:
    raise EnvironmentError("Missing GITHUB_CLIENT_SECRET environment variable.")
if not github_pat and not os.getenv('RENDER'): # Only warn/raise if not on Render and PAT is missing
    print("WARNING: GITHUB_APP_TOKEN not set. Public API requests might hit lower rate limits.")


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
        return {} # Return empty if rate limited
    elif resp.status_code != 200:
        print(f"ERROR: Failed to fetch languages for {repo_full_name}. Status: {resp.status_code}, Response: {resp.text}")
        return {} # Return empty on other errors
    
    data = resp.json()
    total = sum(data.values())
    if total == 0:
        percentages = {} # No languages or empty repo
    else:
        percentages = {lang: round((count / total) * 100, 1) for lang, count in data.items()}
    
    # Store in cache
    repo_language_cache[cache_key] = {'data': percentages, 'timestamp': time.time()}
    
    return percentages

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
    github = OAuth2Session(client_id, scope=["repo"]) 
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
            'https://github.com/login/oauth/access_token',
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
    if is_authenticated:
        # Use user's OAuth token for authenticated requests
        request_headers['Authorization'] = f"token {session['oauth_token']['access_token']}"
        print("DEBUG: Dashboard using user's OAuth token.")
    elif github_pat:
        # Use server-side PAT for unauthenticated public requests
        request_headers['Authorization'] = f"token {github_pat}"
        print("DEBUG: Dashboard using server-side GITHUB_APP_TOKEN.")
    else:
        print("WARNING: No authentication token available for dashboard requests.")

    if is_authenticated:
        try:
            if not username: # Logged-in user viewing their OWN repositories
                user_response = requests.get(f"{GITHUB_API_BASE_URL}/user", headers=request_headers)
                print_rate_limit_info(user_response, "Authenticated User API")
                user_response.raise_for_status()
                user_data = user_response.json()

                page = 1
                while True:
                    repo_response = requests.get(f"{GITHUB_API_BASE_URL}/user/repos", params={"per_page": 100, "page": page, "type": "all"}, headers=request_headers)
                    print_rate_limit_info(repo_response, f"Authenticated Repo API (page {page})")
                    repo_response.raise_for_status()
                    data = repo_response.json()
                    if not data:
                        break
                    
                    for repo in data:
                        repo['private'] = bool(repo.get('private', False))
                        repo['language_percentages'] = get_language_percentages(repo['full_name'], request_headers)
                    all_repos.extend(data)
                    page += 1
                
                user_data['total_repos'] = len(all_repos) # Update total repos count for display

            else: 
                user_resp = requests.get(f"{GITHUB_API_BASE_URL}/users/{username}", headers=request_headers)
                print_rate_limit_info(user_resp, "Authenticated Other User API")
                if user_resp.status_code != 200:
                    error_message = "User not found or an error occurred."
                else:
                    user_data = user_resp.json()
                    page = 1
                    while True:
                        r = requests.get(f"{GITHUB_API_BASE_URL}/users/{username}/repos", params={"per_page": 100, "page": page}, headers=request_headers)
                        print_rate_limit_info(r, f"Authenticated Other User Repos API (page {page})")
                        if r.status_code != 200:
                            error_message = f"Failed to fetch repositories for {username}. It might be a private user or an API error."
                            break
                        data = r.json()
                        if not data:
                            break
                        for repo in data:
                            repo['private'] = bool(repo.get('private', False))
                            # Call get_language_percentages for each repo
                            repo['language_percentages'] = get_language_percentages(repo['full_name'], request_headers)
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

    else: 
        if not username:
            return redirect(url_for('index'))

        u_resp = requests.get(f"{GITHUB_API_BASE_URL}/users/{username}", headers=request_headers)
        print_rate_limit_info(u_resp, "Unauthenticated User API")
        if u_resp.status_code != 200:
            error_message = "User not found." if u_resp.status_code != 403 else "GitHub API rate limit exceeded for public searches. Please try again later or log in."
            return render_template('dashboard.html', user=user_data, repos=all_repos, error=error_message, is_authenticated=False)
        else:
            user_data = u_resp.json()
            page = 1
            while True:
                r_resp = requests.get(f"{GITHUB_API_BASE_URL}/users/{username}/repos", params={"per_page": 100, "page": page}, headers=request_headers)
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
                    repo['language_percentages'] = get_language_percentages(repo['full_name'], request_headers)
                all_repos.extend(data)
                page += 1

    language_colors = {
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
    return render_template(
        'dashboard.html',
        user=user_data,
        repos=all_repos,
        error=error_message,
        is_authenticated=is_authenticated,
        language_colors=language_colors
    )

@app.route('/logout')
def logout(): 
    session.clear()
    flash('You have been logged out.', 'info') # Re-added flash message
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e): 
    return render_template("404.html"), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 1000))
    app.run(host="0.0.0.0", port=port, debug=True)
