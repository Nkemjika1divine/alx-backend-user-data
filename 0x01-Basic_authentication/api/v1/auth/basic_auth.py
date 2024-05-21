#!/usr/bin/env python3
"""Basic Authentication Module"""
from auth import Auth
from models.user import User
from typing import TypeVar
import base64


class BasicAuth(Auth):
    """BasicAuth Class"""

    def extract_base64_authorization_header(self,
                                        authorization_header: str) -> str:
        """Extracting base 64 authorization header"""
        if not authorization_header or type(authorization_header) is not str:
            return None
        
        if authorization_header[0:6] is "Basic ":
            return authorization_header[6:]
        
        return None
    
    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """decode base64 auth header method"""
        if not base64_authorization_header:
            return None
        if type(base64_authorization_header) is not str:
            return None
        
        try:
            return base64.b64decode(base64_authorization_header.encode())\
                    .decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None
    
    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Extract user credentials method"""
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) is not str:
            return None, None
        if ':' in decoded_base64_authorization_header:
            email_password = decoded_base64_authorization_header.split(":")
            email = email_password[0]
            password = ':'.join(email_password[1:])
            return email, password
        return None, None
    

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """User object ffrom credentials method"""
        if not user_email:
            return None
        if not user_pwd:
            return None
        if type(user_pwd) is not str or type(user_email) is not str:
            return None
        try:
            user = User.search({'email': user_email})
        except KeyError:
            return None
        if not user or not user[0].is_valid_password(user_pwd):
            return None
        return user[0]
    
    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current user or None"""
        auth = self.authorization_header(request)
        extract = self.extract_base64_authorization_header(auth)
        decoded = self.decode_base64_authorization_header(extract)
        email, password = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(email, password)
