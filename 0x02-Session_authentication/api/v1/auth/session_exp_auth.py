#!/usr/bin/env python3
"""Session Exp Auth module"""
from api.v1.auth.session_auth import SessionAuth
from os import getenv
from datetime import datetime, timedelta

class SessionExpAuth(SessionAuth):
    """Session exp auth class"""

    def __init__(self):
        """Initializing SessionExpAuth"""
        try:
            self.session_duration = int(getenv("SESSION_DURATION", 0))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """creating a session"""
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        self.user_id_by_session_id[session_id] = {'user_id': user_id,
                                                  'created_at': datetime.now()}
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """retreiving user_id linked to session"""
        if not session_id:
            return None
        session = super().user_id_for_session_id(session_id)
        if not session:
            return None
        if self.session_duration <= 0:
            return session.get('user_id', None)
        created = session.get('created_at', None)
        if not created:
            return None
        expiring = created + timedelta(seconds=self.session_duration)
        if expiring < datetime.now():
            return None
        return session.get('user_id', None)