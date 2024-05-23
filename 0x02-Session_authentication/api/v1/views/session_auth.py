#!/usr/bin/env python3
"""Module for sessions_auth paths"""
from api.v1.views import app_views
from models.user import User
from flask import abort, jsonify, request
from os import environ


@app_views.route("auth_session/login", methods=["POST"], strict_slashes=False)
def login() -> str:
    """POST /auth_session/login || returns JSON of user information"""
    email = request.form.get("email")
    if not email:
        return jsonify({'error': 'email missing'}), 400
    password = request.form.get("password")
    if not password:
        return jsonify({'error': 'password missing'}), 400
    user = User.search({'email': email})
    if not user:
        return jsonify({'error': 'no user found for this email'}), 404
    user = user[0]
    if user.is_valid_password(password):
        return jsonify({'error': 'wrong password'}), 401

    from api.v1.app import auth

    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    response.set_cookie(environ.get("SESSION_NAME"), session_id)
    return response


@app_views.route("auth_session/logout", methods=["DELETE"], strict_slashes=False)
def logout():
    """Logging out of a session"""
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200