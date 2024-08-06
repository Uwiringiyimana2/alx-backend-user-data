#!/usr/bin/env python3
""" Basic authentication modules
"""
import base64
from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """BasicAuth class"""
    def extract_base64_authorization_header(
            self, authorization_header: str
    ) -> str:
        """extract base64 authorization header
        Args:
            authorization_header:
        Returns:
            Base64 part of the Authorization header
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        authorization = authorization_header.split(" ")
        if authorization[0] != "Basic":
            return None
        return authorization[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str
    ) -> str:
        """Decode base64 authorization header
        Args:
            base64_authorization_header: base64 string to decode
        Return:
            decoded value of a Base64 string
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decodedb = base64.b64decode(base64_authorization_header)
            return decodedb.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """extracts user email and password
        Args:
            decoded_base64_authorization_header: string to be extracted
        Return:
            tuple of email and password
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(":", 1)
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """ make user object
        Args:
            user_email
            user_pwd
        Return:
            User object
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        user_list = User.search({'email': user_email})
        if not user_list:
            return None

        for user in user_list:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """retrieves the User instance for a request
        """
        authorization_header = self.authorization_header(request)
        base64_authorization_header = self.extract_base64_authorization_header(
            authorization_header
        )
        decoded_auth = self.decode_base64_authorization_header(
            base64_authorization_header
        )
        user_credentials = self.extract_user_credentials(decoded_auth)
        user = self.user_object_from_credentials(
            user_credentials[0], user_credentials[1]
        )
        return user
