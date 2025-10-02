# main.py

from flask import Flask, render_template, request, redirect, url_for, flash
import firebase_admin
from firebase_admin import credentials, auth
import requests # Used to make requests to Firebase's REST API for login

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- 1. App and Firebase Configuration ---
app = Flask(__name__)
# It's crucial to set a secret key for session management
app.config['SECRET_KEY'] = 'a-super-secret-key-that-is-hard-to-guess'

# Initialize Firebase Admin SDK
# IMPORTANT: Make sure 'firebase_key.json' is in the same directory as this script.
try:
    cred = credentials.Certificate("firebase_key.json")
    firebase_admin.initialize_app(cred)
except Exception as e:
    # This block is to prevent the app from crashing if the key file is not found.
    # In a production environment, you would handle this more robustly.
    print("Warning: Firebase Admin SDK could not be initialized.")
    print(f"Error: {e}")
    print("Please ensure 'firebase_key.json' is present.")


# This is your Web API Key from the Firebase console Project settings.
# It's used for client-side operations like signing in.
FIREBASE_WEB_API_KEY = "AIzaSyDXD6n6JWdJdSsAh_T2B8ySyVijPiUIivQ"
# The URL for Firebase's email/password sign-in REST API endpoint.
FIREBASE_SIGN_IN_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"


# --- 2. Flask-Login Initialization and User Model ---
login_manager = LoginManager()
login_manager.init_app(app)
# If a user tries to access a page that requires login, they are redirected here
login_manager.login_view = 'login'

# This class replaces the SQLAlchemy User model.
# It's a simple object to hold Firebase user data in the Flask session.
class FirebaseUser(UserMixin):
    def __init__(self, uid, email, display_name):
        self.id = uid
        self.email = email
        self.display_name = display_name

# This callback reloads the user object from the user ID (Firebase UID) stored in the session
@login_manager.user_loader
def load_user(user_id):
    try:
        # Fetch the full user data from Firebase using the UID
        firebase_user = auth.get_user(user_id)
        # Create our custom user object to be used by Flask-Login
        return FirebaseUser(
            uid=firebase_user.uid,
            email=firebase_user.email,
            display_name=firebase_user.display_name
        )
    except auth.UserNotFoundError:
        # If the user is not found in Firebase, they can't be logged in.
        return None


# --- 3. Routes ---

# Public Routes
@app.route("/")
def home():
    # The `current_user` global is provided by Flask-Login
    return render_template('index.html', user=current_user)

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('signup'))
        
        try:
            # Use Firebase Admin SDK to create a new user
            new_user = auth.create_user(
                email=email,
                password=password,
                display_name=username
            )
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except firebase_admin.auth.EmailAlreadyExistsError:
            flash('Email address is already registered.', 'error')
            return redirect(url_for('signup'))
        except Exception as e:
            flash(f'An error occurred: {e}', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            # Use Firebase REST API to sign the user in with email and password
            payload = {'email': email, 'password': password, 'returnSecureToken': True}
            response = requests.post(FIREBASE_SIGN_IN_URL, json=payload)
            response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
            
            # If login is successful, get the user's UID from the response
            user_data = response.json()
            uid = user_data['localId']
            
            # Use the UID to load the user into the session with our user_loader
            user = load_user(uid)
            if user:
                login_user(user) # Manage the session with Flask-Login
                flash(f'Welcome back, {user.display_name}!', 'success')
                return redirect(url_for('dashboard'))

        except requests.exceptions.HTTPError as e:
            # Handle common Firebase authentication errors
            error_json = e.response.json().get("error", {})
            error_message = error_json.get("message", "An unknown error occurred.")
            if error_message in ["INVALID_LOGIN_CREDENTIALS", "INVALID_PASSWORD", "EMAIL_NOT_FOUND"]:
                 flash('Invalid email or password. Please try again.', 'error')
            else:
                 flash(f'An error occurred: {error_message}', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/logout")
@login_required # Ensures only logged-in users can access this route
def logout():
    logout_user() # Clears the user session
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('home'))

# Protected Route
@app.route("/dashboard")
@login_required # This decorator protects the route from anonymous access
def dashboard():
    # `current_user` can be used to access the logged-in user's data
    return render_template('dashboard.html', name=current_user.display_name)

# --- 4. Application Runner ---
if __name__ == "__main__":
    # The db.create_all() call is no longer needed as there's no local database
    app.run(debug=True)