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

from abc import abstractmethod
from httpx import Response
from typing import Tuple
from fastapi import status
from sqlalchemy import and_
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta, datetime
from util.auth import AuthenticationError, create_access_token, verify_token
from util.config import settings
from core import sha256
from core.logging import logger
from core.models.user.user import User
from core.models.user.token import JsonWebToken as UserToken, TokenType
from core.database import update_database_record


class IdentityProviderBase:
    """
    This class is the base class for all identity providers.
    """

    def __init__(
            self,
            response: Response,
            client_ip: str | None
    ):
        if response.status_code != status.HTTP_200_OK:
            logger.error(f"Failed to obtain access token from OpenID Connect provider. Response: {response.content}")
            raise AuthenticationError("Failed to obtain access token from IdP.")
        self._response = response
        self._token_data = response.json()
        self._client_ip = client_ip

    @staticmethod
    async def create_token(
            session: AsyncSession,
            user: User,
            token_type: TokenType,
            expires: datetime.date,
            token_name: str | None = None
    ) -> Tuple[UserToken, str]:
        """
        This method creates a new token.
        """
        access_token = create_access_token(
            data={
                "sub": user.email,
                "scopes": user.scopes_str,
                "name": token_name,
                "type": token_type.name
            },
            expires=expires,
        )
        # We add the new access token to the database.
        token = UserToken(
            user=user,
            name=token_name,
            type=token_type,
            revoked=False,
            expiration=expires,
            value=sha256(access_token)
        )
        await session.add(token)
        return token, access_token

    @staticmethod
    async def create_token_for_user(session: AsyncSession, claim_user: User) -> str:
        """
        This method performs all necessary checks
        """
        # If the user does not have any roles, then we do not allow it to log in.
        if len(claim_user.roles) == 0:
            raise AuthenticationError("You are not authorized to access this application.")
        # Check if the user exists and is active. If it exists, then we update its roles.
        user = await session.query(User).filter_by(email=claim_user.email).first()
        if not user:
            user = claim_user
            user.last_login = datetime.now()
            await session.add(user)
        else:
            # If the user is inactive, then we do not allow it to log in.
            if not user.is_active:
                raise AuthenticationError("You are not authorized to access this application.")
            claim_user.id = user.id
            user = await update_database_record(
                session=session,
                source=claim_user,
                source_model=User,
                query_model=User,
                commit=False,
                exclude_unset=True
            )
            # We have to save in local time because PostgreSQL will convert and store it to UTC.
            user.last_login = datetime.now()
            # We revoke all previously active user tokens.
            await session.query(UserToken) \
                .filter(
                    and_(
                        UserToken.user_id == user.id,
                        UserToken.type == TokenType.user,
                        UserToken.revoked == False
                    )
                ).update({UserToken.revoked: True})
        # Finally, we create a valid token for the user.
        access_token_expires = timedelta(minutes=settings.oauth2_access_token_expire_minutes)
        _, access_token = await IdentityProviderBase.create_token(
            session=session,
            user=user,
            token_type=TokenType.user,
            expires=datetime.utcnow() + access_token_expires
        )
        return access_token

    @abstractmethod
    def _get_user_from_token(self, claims: dict) -> User:
        """
        This method converts the token obtained from the identity provider to a user object.
        """
        ...

    async def get_token(self, session: AsyncSession):
        access_token = await verify_token(self._token_data["access_token"])
        user = self._get_user_from_token(access_token)
        token = await self.create_token_for_user(session=session, claim_user=user)
        logger.info(f"User {user.email} successfully logged in.")
        return token
