#!/usr/bin/env python3
""" Session DB Auth
"""
from flask import request
from datetime import datetime, timedelta

from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """ SessionDBAuth class
    """
    def create_session(self, user_id=None):
        """ Overloads create_session
        """
        session_id = super().create_session(user_id)
        if isinstance(session_id, str):
            kwargs = {
              'user_id': user_id,
              'session_id': session_id,
            }
        user_session = UserSession(**kwargs)
        user_session.save()
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ etrieves the user id of the user associated with
        a given session id.
        """
        try:
            user_sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None
        if len(user_sessions) <= 0:
            return None
        cur_time = datetime.now()
        time_span = timedelta(seconds=self.session_duration)
        exp_time = user_sessions[0].created_at + time_span
        if exp_time < cur_time:
            return None
        return user_sessions[0].user_id

    def destroy_session(self, request=None):
        """ Destroys an authenticated session.
        """
        session_id = self.session_cookies(request)
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False
        if len(sessions) <= 0:
            return False
        sessions[0].remove()
        return True
