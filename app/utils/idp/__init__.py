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
from sqlalchemy import update, and_
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta, datetime, timezone

from utils.auth import AuthenticationError, sign_access_token, verify_token
from utils.config import settings
from core.utils import hmac_sha256
from core.utils.logging import logger
from core.models.account import Account, AccessToken, AccessTokenType
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
            account: Account,
            token_type: AccessTokenType,
            expires: datetime.date,
            token_name: str | None = None,
            scopes: list[str] | None = None
    ) -> Tuple[AccessToken, str]:
        """
        This method creates a new token.
        """
        access_token = sign_access_token(
            data={
                "sub": account.email,
                "scopes": scopes or account.scopes_str,
                "name": token_name,
                "type": token_type.name
            },
            expires=expires,
        )
        checksum = hmac_sha256(access_token, settings.hmac_key_access_token)
        if not (result := (await session.execute(
            select(AccessToken).filter_by(checksum=checksum)
        )).scalar_one_or_none()):
            result = AccessToken(
                account=account,
                name=token_name,
                type=token_type,
                revoked=False,
                expiration=expires.replace(tzinfo=timezone.utc),
                checksum=hmac_sha256(access_token, settings.hmac_key_access_token),
            )
            session.add(result)
        return result, access_token

    @staticmethod
    async def create_token_for_account(
            session: AsyncSession,
            claim_account: Account,
    ) -> Tuple[str, AccessToken]:
        """
        This method performs all necessary checks
        """
        # If the account does not have any roles, then we do not allow it to log in.
        if len(claim_account.roles) == 0:
            raise AuthenticationError("You are not authorized to access this application.")
        # Check if the account exists and is active. If it exists, then we update its roles.
        if not (account := (await session.execute(
            select(Account).filter_by(email=claim_account.email)
        )).scalar_one_or_none()):
            account = claim_account
            account.last_login = datetime.now()
            session.add(account)
        else:
            # If the account is inactive, then we do not allow it to log in.
            if not account.is_active():
                raise AuthenticationError("You are not authorized to access this application.")
            claim_account.id = account.id
            account = await update_database_record(
                session=session,
                source=account,
                source_model=Account,
                query_model=Account,
                commit=False,
                exclude_unset=True
            )
            # We have to save in local time because Postgres will convert and store it to UTC.
            account.last_login = datetime.now()
            # We revoke all previously active account tokens.
            await session.execute(
                update(AccessToken)
                .filter(
                    and_(
                        AccessToken.account_id == account.id,
                        AccessToken.type == AccessTokenType.user,
                        not AccessToken.revoked
                    )
                ).values(revoked=True)
            )
        # Finally, we create a valid token for the account.
        access_token_expires = timedelta(minutes=settings.oauth2_access_token_expire_minutes)
        token, access_token = await IdentityProviderBase.create_token(
            session=session,
            account=account,
            token_type=AccessTokenType.user,
            expires=datetime.utcnow() + access_token_expires
        )
        return access_token, token

    @abstractmethod
    def _get_account_from_token(self, claims: dict) -> Account:
        """
        This method converts the token obtained from the identity provider to an account object.
        """
        ...

    async def get_token(self, session: AsyncSession) -> Tuple[str, AccessToken]:
        access_token = await verify_token(self._token_data["access_token"])
        account = self._get_account_from_token(access_token)
        token = await self.create_token_for_account(session=session, claim_account=account)
        logger.info(f"Account {account.email} successfully logged in.")
        return token
