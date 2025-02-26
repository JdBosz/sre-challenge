import sqlite3
import logging
from flask import Flask, session, redirect, url_for, request, render_template, abort
import os
import bcrypt


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))
#app.secret_key = b"192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf"
app.logger.setLevel(logging.INFO)

def get_db_connection():
    connection = sqlite3.connect("database.db")
    connection.row_factory = sqlite3.Row
    return connection


def is_authenticated():
    if "username" in session:
        return True
    return False

def authenticate(username, password):
    """Authenticate de user dmv username en password."""
    if not username or not password:
        app.logger.warning("username or password missing...")
        return False

    connection = get_db_connection()
    try:
        # Search user in the database op by username
        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",(username,)).fetchone()

        # Check if user exist
        if user:
            # Get hash password from database
            stored_hash = user['password']

            # comparte password with hash password
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):  # compare with bcrypt
                app.logger.info(f"The user '{username}' has logged in succesfully.")
                session["username"] = username
                return True
            else:
                app.logger.warning(f" failed loging attempt for user '{username}', password incorrect.")
                return False
        else:
            app.logger.warning(f"User '{username}' does not existig.")
            return False
    finally:
        connection.close()

@app.route("/")
def index():
    return render_template("index.html", is_authenticated=is_authenticated())


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles the log-in of user."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if authenticate(username, password):
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
