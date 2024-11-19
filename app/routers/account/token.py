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

from __future__ import annotations

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"

import jose
import logging
from typing import List, Tuple
from jose import JWTError, jwt
from fastapi import Request
from pydantic import ValidationError
from core.utils import AuthenticationError, sha256
from core.models.account import Account
from core.models.account.token import AccessToken, AccessTokenType
from utils.config import settings
from sqlalchemy import or_, and_, not_
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession


async def verify_token(
        session: AsyncSession,
        request: Request,
        logger: logging.Logger,
        _x_real_ip: List[str],
        token: str
) -> Tuple[Account, dict]:
    """
    Verifies the integrity of the given token.
    """
    # Check 1: Verify the integrity of the token.
    try:
        payload = jwt.decode(token, settings.oauth2_secret_key, algorithms=[settings.oauth2_algorithm])
        email: str = payload.get("sub")
        if email is None:
            raise AuthenticationError()
    except jose.exceptions.ExpiredSignatureError:
        raise AuthenticationError()
    except (JWTError, ValidationError) as ex:
        logger.exception(ex)
        raise AuthenticationError()
    # Check 2: Check whether the account exists and is active.
    account = (await session.execute(select(Account).filter_by(email=email))).scalar_one_or_none()
    if account is None or not account.is_active or not account.roles:
        raise AuthenticationError("Your account has been locked. Please contact the administrator.")
    # Check 3: Check whether the account's token has been revoked.
    result = await session.execute(
        select(AccessToken).filter(
            and_(
                AccessToken.account_id == account.id,
                or_(AccessToken.type == AccessTokenType.user, AccessToken.type == AccessTokenType.api),
                AccessToken.value == sha256(token),
                not_(AccessToken.revoked)
            )
        )
    )
    access_token = result.scalar_one_or_none()
    if access_token is None or access_token.revoked:
        raise AuthenticationError("Token has been revoked. Please login again.")
    # Check 4: Check CSRF token
    if request.method in ["POST", "PUT", "DELETE"]:
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != access_token.value:
            raise AuthenticationError("Invalid CSRF token.")
    return account, payload
