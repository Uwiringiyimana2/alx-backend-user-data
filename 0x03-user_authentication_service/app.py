#!/usr/bin/env python3
""" Basic flask app
"""
from flask import (
    Flask,
    jsonify,
    request,
    abort,
    redirect,
    url_for,
)
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route("/")
def index():
    """Welcome message"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users():
    """ POST /users
    Args:
      - email
      - password
    Return:
      - {"email": "<registered email>", "message": "user created"}
        if successful registered user
      - {"message": "email already registered"} with status code 400
        if user already registed
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = AUTH.register_user(email, password)
        if user:
            return jsonify(
                {"email": email, "message": "user created"}
            )
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """ POST /sessions
    Args:
      - email
      - password
    Return:
      - new session
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if AUTH.valid_login(email, password):
        session = AUTH.create_session(email)
        res = jsonify({"email": email, "message": "logged in"})
        res.set_cookie("session_id", session)
        return res
    abort(401)


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """ DELETE /sessions
    """
    user = None
    session_id = request.cookies.get("session_id")
    if not session_id:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return(redirect(url_for('index')))
    abort(403)


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile():
    """ GET /profile
    """
    session_id = request.cookies.get("session")
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
