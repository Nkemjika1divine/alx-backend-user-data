#!/usr/bin/env python3
"""Auth module"""
from bcrypt import hashpw, gensalt, checkpw
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from user import User
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """Returns a hashed password of users"""
    return hashpw(password.encode("utf8"), gensalt())


def _generate_uuid() -> str:
    """Generatess a uuid for users"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database"""

    def __init__(self):
        """Initializing the class"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a user into the database"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            user = self._db.add_user(email, _hash_password(password))
        else:
            raise ValueError("User {} already exists".format(email))
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates login credentials of users"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        return checkpw(password.encode("utf-8"), user.hashed_password)

    def create_session(self, email: str) -> str:
        """creates a session"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """retrieve a user based on the session ID provided"""
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: str) -> None:
        """destroys a session"""
        if user_id:
            self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Gets a token for resetting password"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError()
        token = _generate_uuid()
        self._db.update_user(user.id, reset_token=token)
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """Uses a password to update a token"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError()
        self._db.update_user(user.id,
                             hashed_password=_hash_password(password),
                             reset_token=None)
