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


import httpx
import fastapi
import logging
import functools
from httpx import HTTPStatusError
from datetime import datetime
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from util.config import settings, COOKIE_NAME
from core import LuminaException
from core.models.user.role import RoleEnum, ApiPermissionEnum
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from pydantic import BaseModel
from typing import Dict, List
from fastapi.security.utils import get_authorization_scheme_param
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED

logger = logging.getLogger(__name__)


class OAuth2PasswordBearerWithCookie(fastapi.security.OAuth2):
    """
    This class enforces JWT authentication via cookie access_token.

    Source: https://github.com/tiangolo/fastapi/issues/796
    """
    def __init__(
            self,
            token_url: str,
            scheme_name: str | None = None,
            scopes: Dict[str, str] | None = None,
            auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": token_url, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> str | None:
        authorization: str = request.cookies.get(COOKIE_NAME)
        authorization = f"Bearer {authorization}"
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param


oauth2_scheme = OAuth2PasswordBearerWithCookie(
    token_url="/api/v1/token",
    scopes={item.name: item.value for item in ApiPermissionEnum},
)


class Token(BaseModel):
    access_token: str
    token_type: str


class AuthenticationError(LuminaException):
    def __init__(self, message: str = "Could not validate user."):
        super().__init__(message)


class IdpConnectionError(LuminaException):
    def __init__(
            self,
            message: str = "Server could not connect to IdP to obtain your claim. Please try again later."
    ):
        super().__init__(message)


class UserUpdateError(LuminaException):
    def __init__(self, message: str):
        super().__init__(message)


def get_roles(roles: List[str]) -> List[RoleEnum]:
    """
    Get the roles from the given list of strings.
    """
    return [RoleEnum[role] for role in roles if role in RoleEnum.__members__]


@functools.lru_cache()
async def get_jwks():
    """
    Get the JWKS from the Identity Provider.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(settings.jwks_url)
    if response.status_code != 200:
        raise IdpConnectionError()
    return response.json()


async def verify_token(token: str):
    """
    Obtains the public key from the JWKS endpoint and verifies the given token.
    """
    try:
        # Fetch the public key from JWKS endpoint
        cache = await get_jwks()
        jwks = cache.result()
        header = jwt.get_unverified_header(token)
        kid = header['kid']
        rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == kid:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if len(rsa_key) == 0:
            raise ValueError("No matching public key found.")
        payload = jwt.decode(
            token=token,
            key=rsa_key,
            algorithms=["RS256"],
            audience=settings.audience,
            issuer=settings.issuer
        )
        return payload
    except HTTPStatusError as e:
        logger.exception(e)
        raise IdpConnectionError() from e
    except Exception as e:
        logger.exception(e)
        raise AuthenticationError("It seems you are not authorized to access this application.") from e


def create_access_token(data: dict, expires: datetime) -> str:
    """
    Create an access token for the given data.
    :param data: The dict to be signed.
    :param expires: Date when the token expires.
    :return:
    """
    to_encode = data.copy()
    to_encode.update({"exp": expires})
    encoded_jwt = jwt.encode(to_encode, settings.oauth2_secret_key, algorithm=settings.oauth2_algorithm)
    return encoded_jwt
