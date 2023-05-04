#!/usr/bin/env python3
"""
Module for authentication using Basic auth
"""

from typing import TypeVar
from api.v1.auth.auth import Auth
import base64
from models.user import User


class BasicAuth(Auth):
    """Class for authentication using Basic auth"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """Extracts the base64 encoded authorization header from a request"""
        if not authorization_header or not isinstance(authorization_header, str) or not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split(' ')[-1]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """Decodes the base64 encoded string to its original form"""
        if not base64_authorization_header or not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header.encode('utf-8'))
            return decoded_bytes.decode('utf-8')
        except base64.binascii.Error:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> tuple:
        """Extracts the email and password from the decoded string"""
        if not decoded_base64_authorization_header or not isinstance(decoded_base64_authorization_header, str) or ':' not in decoded_base64_authorization_header:
            return None, None
        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> User:
        """Searches the database for a user with the given email and password and returns the user object"""
        if not user_email or not isinstance(user_email, str) or not user_pwd or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({"email": user_email})
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
        except Exception:
            return None

    def current_user(self, request=None) -> User:
        """Returns the user object for the current request"""
        auth_header = self.authorization_header(request)
        if auth_header:
            token = self.extract_base64_authorization_header(auth_header)
            if token:
                decoded = self.decode_base64_authorization_header(token)
                if decoded:
                    email, password = self.extract_user_credentials(decoded)
                    if email:
                        return self.user_object_from_credentials(email, password)
        return None

