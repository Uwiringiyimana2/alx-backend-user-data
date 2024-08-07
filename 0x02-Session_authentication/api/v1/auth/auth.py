#!/usr/bin/env python3
"""Auth module
"""
import re
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
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
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
