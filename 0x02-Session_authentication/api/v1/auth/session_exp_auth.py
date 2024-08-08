#!/usr/bin/env python3
""" Expiration Auth
"""
from api.v1.auth.session_auth import SessionAuth
from os import getenv
from datetime import datetime, timedelta
from flask import request


class SessionExpAuth(SessionAuth):
    """ SessionExpAuth class
    """
    def __init__(self):
        """ Overload Initialization
        """
        try:
            session_dur = int(getenv('SESSION_DURATION', '0'))
        except ValueError:
            session_dur = 0
        self.session_duration = session_dur

    def create_session(self, user_id=None):
        """ Overload create_session
        Args:
            user_id: User id
        Return:
            - Session ID if success
            - None if super() can't create a Session Id
        """
        session_id = super().create_session(user_id)
        if type(session_id) != str:
            return None
        self.user_id_by_session_id[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ Overload user_id_for_session_id(self, session_id=None)
        Args:
            session_id: session ID
        Return:
            - user_id if successful
        """
        if session_id in self.user_id_by_session_id:
            session_dict = self.user_id_by_session_id[session_id]
            if self.session_duration <= 0:
                return session_dict['user_id']
            if 'created_at' not in session_dict:
                return None
            cur_time = datetime.now()
            time_span = timedelta(seconds=self.session_duration)
            exp_time = session_dict['created_at'] + time_span
            if exp_time < cur_time:
                return None
            return session_dict['user_id']
