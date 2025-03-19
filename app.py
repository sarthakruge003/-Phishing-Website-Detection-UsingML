from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_session import Session
from featureExtractor import featureExtraction  # Ensure this module is available
from pycaret.classification import load_model, predict_model
import os

# Load the machine learning model
model = load_model('model/phishingdetection')

def predict(url):
    """Predict the phishing risk of the given URL."""
    data = featureExtraction(url)
    result = predict_model(model, data=data)
    prediction_score = result['prediction_score'][0]
    prediction_label = result['prediction_label'][0]
    
    # Convert numerical labels to human-readable labels
    if prediction_label == 1:
        prediction_label_text = "Unsafe"
        add_to_blocklist(url)  # Automatically add unsafe URLs to the blocklist
    else:
        prediction_label_text = "Safe"

    return {
        'url': url,
        'prediction_label': prediction_label_text,
        'prediction_score': prediction_score * 100,
    }

def add_to_blocklist(url):
    """Add the URL to the blocklist."""
    with open(BLOCKLIST_FILE, 'a') as file:
        file.write(url + '\n')
    flash('URL added to blocklist.', 'success')

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a random secret key

# Configure Flask-Session to use filesystem-based sessions
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = 'session_files'  # Use a directory for session files
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 100
Session(app)

# Sample credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

USER_CREDENTIALS = {
    'user1': 'user123',
    'user2': 'password2',
    'user3': 'password3',
    'user4': 'password4'
}

# Blocklist storage
BLOCKLIST_FILE = 'blocklist.txt'

# Ensure the session file directory exists
if not os.path.exists('session_files'):
    os.makedirs('session_files')

if not os.path.exists(BLOCKLIST_FILE):
    open(BLOCKLIST_FILE, 'w').close()  # Create the blocklist file if it does not exist

@app.route("/", methods=["GET", "POST"])
def index():
    if 'user' not in session:
        return redirect(url_for('login_options'))

    data = None
    blocklist_status = None
    url = None

    if request.method == "POST":
        url = request.form.get("url")
        if url:
            data = predict(url)
            if is_blocklisted(url):
                blocklist_status = "This website is blocklisted by admin."

    return render_template("index.html", url=url, data=data, blocklist_status=blocklist_status)

@app.route("/get_blocklist")
def get_blocklist():
    """Return the blocklisted URLs as JSON."""
    with open(BLOCKLIST_FILE, 'r') as file:
        blocklisted_urls = file.read().splitlines()
    return {'urls': blocklisted_urls}

@app.route("/about")
def about():
    if 'user' not in session:
        return redirect(url_for('login_options'))
    return render_template("about.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if 'user' not in session:
        return redirect(url_for('login_options'))
    if request.method == "POST":
        # Handle form submission logic here
        pass
    return render_template("contact.html")

@app.route("/about_admin")
def about_admin():
    if 'user' not in session or session['user'] != ADMIN_USERNAME:
        return redirect(url_for('login_options'))
    return render_template("about_admin.html")

@app.route("/contact_admin", methods=["GET", "POST"])
def contact_admin():
    if 'user' not in session or session['user'] != ADMIN_USERNAME:
        return redirect(url_for('login_options'))
    if request.method == "POST":
        # Handle form submission logic here
        pass
    return render_template("contact_admin.html")

@app.route("/login_options")
def login_options():
    return render_template("landing_page.html")

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['user'] = username
            return redirect(url_for('admin_index'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template("admin_login.html")

@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if USER_CREDENTIALS.get(username) == password:
            session['user'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template("user_login.html")

@app.route("/admin", methods=["GET", "POST"])
def admin_index():
    if 'user' not in session or session['user'] != ADMIN_USERNAME:
        return redirect(url_for('login_options'))

    data = None
    blocklist_status = None
    url = None

    if request.method == "POST":
        url = request.form.get("url")

        # Check if URL is to be added to blocklist
        if 'add_to_blocklist' in request.form:
            if url:
                add_to_blocklist(url)  # Add URL to blocklist
                return redirect(url_for('admin_index'))

        # Predict the URL and check blocklist status
        if url:
            data = predict(url)
            if is_blocklisted(url):
                blocklist_status = "This website is blocklisted by admin."

    return render_template("admin_index.html", url=url, data=data, blocklist_status=blocklist_status)

@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('login_options'))

def is_blocklisted(url):
    """Check if the URL is in the blocklist."""
    with open(BLOCKLIST_FILE, 'r') as file:
        blocklisted_urls = file.read().splitlines()
    return url in blocklisted_urls


if __name__ == "__main__":
    # Clear session files on app start
    if os.path.exists('session_files'):
        for f in os.listdir('session_files'):
            os.remove(os.path.join('session_files', f))
    app.run(debug=True)
