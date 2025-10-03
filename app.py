import os
import json
from Crypto.Cipher import AES
from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from dotenv import load_dotenv

# -------------------------------
# Load environment variables
# -------------------------------
load_dotenv()  # Load .env file if exists
AES_KEY = os.getenv("AES_KEY", "16charkeyforaes!").encode()  # Must be 16/24/32 bytes
FLASK_SECRET = os.getenv("FLASK_SECRET_KEY", "dev-secret")

# -------------------------------
# Initialize Flask app
# -------------------------------
app = Flask(__name__)
app.secret_key = FLASK_SECRET

# -------------------------------
# File upload setup
# -------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB limit

# -------------------------------
# Helper functions
# -------------------------------
def load_users():
    """Load users from users.json"""
    with open("users.json", "r") as f:
        return json.load(f)

def encrypt_file(data: bytes, key: bytes):
    """Encrypt data using AES-GCM"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, tag, ciphertext

def decrypt_file(nonce: bytes, tag: bytes, ciphertext: bytes, key: bytes):
    """Decrypt data using AES-GCM"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# -------------------------------
# Routes
# -------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        users = load_users()

        if username not in users:
            flash("❌ User does not exist")
            return redirect(url_for("login"))

        if check_password_hash(users[username], password):
            session["user"] = username
            flash("✅ Login successful!")
            return redirect(url_for("index"))
        else:
            flash("❌ Incorrect password")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    """Dashboard page (requires login)"""
    if "user" in session:
        return render_template("dashboard.html", user=session["user"])
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    """Logout user"""
    session.pop("user", None)
    flash("Logged out")
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename + ".enc")

        data = file.read()
        nonce, tag, ciphertext = encrypt_file(data, AES_KEY)

        with open(save_path, "wb") as f:
            f.write(nonce + tag + ciphertext)

        flash(f"Uploaded and encrypted: {filename}")
        return redirect(url_for("index"))

    # --- List all uploaded files (decryptable) ---
    uploaded_files = [f[:-4] for f in os.listdir(app.config["UPLOAD_FOLDER"]) if f.endswith(".enc")]

    return render_template("index.html", files=uploaded_files)


@app.route("/download/<path:filename>")
def download(filename):
    """Download and decrypt file"""
    enc_path = os.path.join(app.config["UPLOAD_FOLDER"], filename + ".enc")

    with open(enc_path, "rb") as f:
        file_data = f.read()

    # Extract nonce, tag, ciphertext
    nonce, tag, ciphertext = file_data[:16], file_data[16:32], file_data[32:]
    decrypted_data = decrypt_file(nonce, tag, ciphertext, AES_KEY)

    return decrypted_data, 200, {
        "Content-Disposition": f"attachment; filename={filename}",
        "Content-Type": "application/octet-stream"
    }

# -------------------------------
# Run Flask app
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
