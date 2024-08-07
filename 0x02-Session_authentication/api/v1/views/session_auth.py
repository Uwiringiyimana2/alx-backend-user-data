#!/usr/bin/env python3
""" Module of session_auth views
"""
import os
from flask import jsonify, abort, request
from api.v1.views import app_views
from models.user import User
from typing import Tuple


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """Login"""
    email = request.form.get('email')
    if email is None or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400
    password = request.form.get('password')
    if password is None or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400
    try:
        user_list = User.search({'email': email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404
    if len(user_list) <= 0:
        return jsonify({"error": "no user found for this email"}), 404
    if user_list[0].is_valid_password(password):
        from api.v1.app import auth
        session_id = auth.create_session(getattr(user_list[0], 'id'))
        res = jsonify(user_list[0].to_json())
        res.set_cookie(os.getenv("SESSION_NAME"), session_id)
        return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route(
        '/auth_session/logout', methods=['DELETE'], strict_slashes=False
)
def logout():
    """DELETE /api/v1/auth_session/logout
    return an empty JSON
    """
    from api.v1.app import auth
    is_destroyed = auth.destroy_session(request)
    if not is_destroyed:
        abort(404)
    return jsonify({}), 200
