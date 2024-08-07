#!/usr/bin/env python3
""" Session authentication mechanism
"""
import uuid
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """Session Auth class"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """creates a Session ID for a user_id
        Args:
            user_id: user id
        Return:
            - session id if successful
            - None if user_id id None or user_id not string
        """
        if user_id and isinstance(user_id, str):
            session_id = str(uuid.uuid4())
            SessionAuth.user_id_by_session_id[session_id] = user_id
            return session_id
        return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ User ID based on a Session ID
        Args:
            session_id:
        Return:
            - None if session_id is none or not string
            - user_id if success
        """
        if session_id and isinstance(session_id, str):
            return SessionAuth.user_id_by_session_id.get(session_id)
        return None

    def current_user(self, request=None):
        """ return value based on a Cookie value
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        """ Destroy session
        """
        if request:
            session_id = self.session_cookie(request)
            if not session_id:
                return False
            user_id = self.user_id_for_session_id(session_id)
            if user_id:
                del self.user_id_by_session_id[session_id]
                return True
        return False
