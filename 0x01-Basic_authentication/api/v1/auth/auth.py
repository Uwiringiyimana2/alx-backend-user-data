#!/usr/bin/env python3
"""Auth module
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """ Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Authentication requirement
        Args:
            Path:
            excluded_paths:
        Returns:
            False
        """
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        for ex_path in excluded_paths:
            if ex_path.endswith('*'):
                if path.startswith(ex_path[:-1]):
                    return False
            elif path == ex_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Authorization Header
        Args:
            request: Flask request object
        returns:
            None
        """
        if request is None:
            return None
        if request.headers.get('Authorization') is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current user
        Args:
            request: Flask request object
        Return:
            user
        """
        return None
