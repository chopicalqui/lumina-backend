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

import os
import enum
from pathlib import Path
from core.utils.config import SettingsBase


class IdentityProviderType(enum.IntEnum):
    adfs = enum.auto()
    keycloak = enum.auto()


CURRENT_DIRECTORY = os.path.dirname(__file__)
APP_DIRECTORY = Path(__file__).parent.parent
API_PREFIX = "/api/v1"
COOKIE_NAME = "access-token"
CSRF_COOKIE_NAME = "x-token"


class Settings(SettingsBase):
    """
    This class manages the settings of the application.
    """
    def __init__(self):
        super().__init__()
        idp_type = os.getenv("IDP")
        idp_types = [item.name for item in IdentityProviderType]
        if idp_type not in idp_types:
            raise ValueError(
                f"Environment variable IDP does not contain a valid value. Valid values are: {', '.join(idp_types)}"
            )
        self.idp_type = IdentityProviderType[idp_type]
        self.https = os.getenv("HTTPS").lower() == "true"
        self.oauth2_scheme = os.getenv("OAUTH2_SCHEME")
        self.oauth2_secret_key = os.getenv("OAUTH2_SECRET_KEY")
        self.oauth2_algorithm = os.getenv("OAUTH2_ALGORITHM")
        self.oauth2_access_token_expire_minutes = int(os.getenv("OAUTH2_ACCESS_TOKEN_EXPIRE_MINUTES", 30))
        self.hmac_key_access_token = os.getenv("HMAC_KEY_ACCESS_TOKEN")
        self.client_id = os.getenv("CLIENT_ID")
        self.client_secret = os.getenv("CLIENT_SECRET")
        self.redirect_uri = os.getenv("REDIRECT_URI")
        self.issuer = os.getenv("ISSUER")
        self.audience = os.getenv("AUDIENCE")
        self.token_url = os.getenv("TOKEN_URL")
        self.authorization_url = os.getenv("AUTHORIZATION_URL")
        self.jwks_url = os.getenv("JWKS_URL")


settings = Settings()
