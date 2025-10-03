import json
import os
from werkzeug.security import generate_password_hash

USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def create_user(username, password):
    users = load_users()

    if username in users:
        print(f"User '{username}' already exists!")
        return

    # ✅ Directly store hash string (no nested dict)
    users[username] = generate_password_hash(password)
    save_users(users)
    print(f"User '{username}' created successfully!")

if __name__ == "__main__":
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    create_user(username, password)
