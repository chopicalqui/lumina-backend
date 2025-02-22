# This file is part of Lumina.
#
# Lumina is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Lumina is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Lumina. If not, see <https://www.gnu.org/licenses/>.

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2025 Lukas Reiter"
__license__ = "GPLv3"

from core.utils import AuthenticationError


class InvalidCsrfTokenError(AuthenticationError):
    """
    Raised when the CSRF token is invalid.
    """
    def __init__(self, **kwargs):
        super().__init__("CSRF token is invalid.", **kwargs)


class AccountLockedError(AuthenticationError):
    """
    Raised when the account is locked.
    """
    def __init__(self, **kwargs):
        super().__init__("The account has been locked.", **kwargs)


class AuthenticationErrorSkipLogging(AuthenticationError):
    """
    Raised when authentication failed but should not be logged.
    """
    def __init__(self, message: str, **kwargs):
        super().__init__(message, **kwargs)


class SessionRevokedError(AuthenticationErrorSkipLogging):
    """
    Raised when the token was revoked.
    """
    def __init__(self, **kwargs):
        super().__init__("Token has been revoked.", **kwargs)


class SessionTokenMissingError(AuthenticationErrorSkipLogging):
    """
    Raised when the session token is missing.
    """
    def __init__(self, **kwargs):
        super().__init__("Token is missing.", **kwargs)


class SessionExpiredError(AuthenticationErrorSkipLogging):
    """
    Raised when the token has expired.
    """
    def __init__(self, **kwargs):
        super().__init__("Token has expired.", **kwargs)


class TokenValidationError(AuthenticationErrorSkipLogging):
    """
    Raised when the token validation fails.
    """
    def __init__(self, **kwargs):
        super().__init__("Token validation failed.", **kwargs)
