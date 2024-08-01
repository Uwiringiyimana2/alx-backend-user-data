#!/usr/bin/env python3
"""Encrypting passwords"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Encrypting password"""
    password_byte = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_byte, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """hashed_password: bytes"""
    password_byte = password.encode("utf-8")
    return bcrypt.checkpw(password_byte, hashed_password)
