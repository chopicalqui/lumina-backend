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
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"


from . import IdentityProviderBase
from util.auth import AuthenticationError, get_roles
from util.config import settings
from core.models.user.user import User


class KeycloakIdentityProvider(IdentityProviderBase):
    """
    Identity provider class to integrate Lumina with the identity provider Keycloak.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _get_user_from_token(self, claims: dict) -> User:
        """
        This method converts the token obtained from the identity provider to a user object.
        """
        if claims["azp"] != settings.client_id:
            raise AuthenticationError("The given access token was not issued for this application.")
        roles = claims["resource_access"][settings.client_id]["roles"]
        email = claims["email"]
        name = claims["name"]
        email_verified = claims["email_verified"]
        if not email_verified:
            raise AuthenticationError("Your email address has not been verified yet.")
        return User(
            email=email,
            roles=get_roles(roles),
            locked=False,
            full_name=name,
            client_ip=self._client_ip
        )
