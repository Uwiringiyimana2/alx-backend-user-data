#!/usr/bin/env python3
"""Hashing password"""
import bcrypt
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Password Hashing with bcrypt"""
    password = password.encode("utf-8")
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register User"""
        user = self._db._session.query(User).filter_by(email=email).first()
        if user:
            raise ValueError(f"User {email} already exists")
        hashedpw = _hash_password(password)
        new_user = self._db.add_user(email, hashedpw)
        return new_user
