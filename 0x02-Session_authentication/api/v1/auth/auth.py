#!/usr/bin/env python3
"""Authentication module"""
import os
from flask import request
from typing import List, TypeVar


class Auth:
    """The Auth Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require_auth method"""
        if path is None or excluded_paths is None:
            return True

        if path in excluded_paths:
            return False
        else:
            path_with_slash = path + '/'
            if path_with_slash in excluded_paths:
                return False
            else:
                for paths in excluded_paths:
                    if paths[-1] == '*':
                        count = 0
                        for i in paths:
                            count += 1
                            if path[0:count - 1] == paths[0:-1]:
                                return False
                            else:
                                return True
        return False

    def authorization_header(self, request=None) -> str:
        """authorization_header method"""
        if not request:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar("User"):
        """current_user method"""
        return None

    def session_cookie(self, request=None):
        """Returns a cookie value from a request"""
        if not request:
            return None
        return request.cookies.get(os.environ.get('SESSION_NAME', None))
