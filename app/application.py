import sqlite3
import logging
from flask import Flask, session, redirect, url_for, request, render_template, abort
import os
import bcrypt


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))
#app.secret_key = b"192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf"
app.logger.setLevel(logging.INFO)

# session-cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True 
app.config["SESSION_COOKIE_SAMESITE"] = "None"


def get_db_connection():
    connection = sqlite3.connect("database.db")
    connection.row_factory = sqlite3.Row
    return connection


def is_authenticated():
    if "username" in session:
        return True
    return False

def authenticate(username, password):
    """Authenticeert een gebruiker met gegeven gebruikersnaam en wachtwoord."""
    if not username or not password:
        app.logger.warning("Gebruikersnaam of wachtwoord ontbreekt.")
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
                app.logger.info(f"De gebruiker '{username}' is succesvol ingelogd.")
                session["username"] = username
                return True
            else:
                app.logger.warning(f"Mislukte inlogpoging voor gebruiker '{username}', wachtwoord is incorrect.")
                return False
        else:
            app.logger.warning(f"Gebruiker '{username}' bestaat niet.")
            return False
    finally:
        connection.close()

@app.route("/")
def index():
    return render_template("index.html", is_authenticated=is_authenticated())


@app.route("/login", methods=["GET", "POST"])
def login():
    """Behandelt het inloggen van de gebruiker."""
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
