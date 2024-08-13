#!/usr/bin/env python3
"""Hashing password"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """Password Hashing with bcrypt"""
    password = password.encode("utf-8")
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed
