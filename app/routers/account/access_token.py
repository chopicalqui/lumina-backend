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

from uuid import UUID
from typing import List, Dict
from datetime import datetime
from fastapi import Body, Depends, Security, APIRouter, status
from sqlalchemy import and_
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.utils.status import AlertSeverityEnum
from utils.idp import IdentityProviderBase
from core.utils import (
    AuthorizationError, NotFoundError, UniqueConstraintError, InvalidDataError, StatusMessage
)
from .account import API_ME, get_current_account
from core.models.account import (
    Account, ApiPermissionEnum, AccessToken, AccessTokenRead, AccessTokenType, ROLE_PERMISSION_MAPPING,
    AccessTokenCreate, AccessTokenReadTokenValue, AccessTokenUpdate
)
from core.database import get_db, get_by_id

API_ME_ACCESS_TOKEN_SUFFIX = "/access-tokens"


router = APIRouter(
    prefix=API_ME,
    tags=["access token"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Incomplete or invalid data"},
        404: {"description": "Not found"},
        405: {"description": "Method not allowed"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get(API_ME_ACCESS_TOKEN_SUFFIX, response_model=List[AccessTokenRead])
async def read_access_tokens(
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.access_token_read.name]),
    session: AsyncSession = Depends(get_db)
):
    """
    Allows users to obtain their access tokens.
    """
    result = (
        await session.execute(
            select(AccessToken).filter(
                and_(AccessToken.account_id == account.id, AccessToken.type == AccessTokenType.api)
            )
        )
    ).scalars().all()
    return result


@router.get(API_ME_ACCESS_TOKEN_SUFFIX + "/{id}", response_model=AccessTokenRead)
async def read_access_token_by_id(
    id: UUID,
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.access_token_read.name]),
    session: AsyncSession = Depends(get_db)
):
    """
    Allows users to obtain an access tokens.
    """
    result = (
        await session.execute(
            select(AccessToken).filter(
                and_(
                    AccessToken.account_id == account.id,
                    AccessToken.type == AccessTokenType.api,
                    AccessToken.id == id
                )
            )
        )
    ).scalars().one_or_none()
    if not result:
        raise NotFoundError(f"Access token does not exist.")
    return result


@router.get("/scopes", response_model=List[Dict[str, str]])
def read_scopes(
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.access_token_read.name])
):
    """
    Allows users to obtain the available scopes.
    """
    result = set()
    for role in account.roles:
        info = ROLE_PERMISSION_MAPPING[role.name]
        result.update((item, ApiPermissionEnum[item].value.description) for item in info)
    return [{"id": key, "label": value} for key, value in sorted(result, key=lambda x: x[1])]


@router.post(API_ME_ACCESS_TOKEN_SUFFIX, response_model=AccessTokenReadTokenValue)
async def create_access_token(
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.access_token_create.name]),
    session: AsyncSession = Depends(get_db),
    body: AccessTokenCreate = Body(...)
):
    """
    Allows users to create an access token.
    """
    possible_scopes = []
    # Obtain all user permissions
    for role in account.roles:
        possible_scopes += [item for item in ROLE_PERMISSION_MAPPING.get(role.name, [])]
    # Ensure that only permissions within the user's privileges are used
    for scope in body.scopes:
        if scope not in possible_scopes:
            raise AuthorizationError(
                account=account,
                message=f"User does not have the permission '{scope}'."
            )
    scopes = sorted(body.scopes)
    # Validate unique constraints
    if (await session.execute(
        select(AccessToken).filter(
            and_(
                AccessToken.name == body.name,
                AccessToken.account_id == account.id,
                AccessToken.type == AccessTokenType.api,
                AccessToken.expiration == body.expiration,
                AccessToken.scopes == scopes
            )
        )
    )).scalar_one_or_none():
        raise UniqueConstraintError("Access token with same name, scopes and expiration already exists.")
    if body.expiration < datetime.now():
        raise InvalidDataError("Expiration date must be in the future.")
    if len(body.scopes or []) == 0:
        raise InvalidDataError("At least one scope must be provided.")
    # Create the access token
    user = await get_by_id(session, Account, account.id)
    new_access_token, raw_access_token = await IdentityProviderBase.create_token(
        session=session,
        account=user,
        token_type=AccessTokenType.api,
        expires=body.expiration,
        token_name=body.name,
        scopes=scopes
    )
    new_access_token.scopes = [ApiPermissionEnum[item] for item in scopes]
    await session.commit()
    await session.refresh(new_access_token)
    result = AccessTokenReadTokenValue.model_construct(**new_access_token.dict(), value=raw_access_token)
    return result


@router.put(API_ME_ACCESS_TOKEN_SUFFIX, response_model=StatusMessage)
async def update_access_token(
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.access_token_update.name]),
    session: AsyncSession = Depends(get_db),
    body: AccessTokenUpdate = Body(...)
):
    """
    Allows users to update an access token.
    """
    if token := (await session.execute(
        select(AccessToken).filter(
            and_(
                AccessToken.id == body.id,
                AccessToken.account_id == account.id,
                AccessToken.type == AccessTokenType.api
            )
        )
    )).scalars().one_or_none():
        token.revoked = body.revoked
        await session.commit()
    return StatusMessage(
        status=status.HTTP_200_OK,
        severity=AlertSeverityEnum.success,
        message="Access token updated successfully."
    )


@router.delete(API_ME_ACCESS_TOKEN_SUFFIX + "/{token_id}", response_model=StatusMessage)
async def delete_access_token(
    token_id: UUID,
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.access_token_delete.name]),
    session: AsyncSession = Depends(get_db)
):
    """
    Allows users to delete an access token.
    """
    if token := (await session.execute(
        select(AccessToken).filter(
            and_(
                AccessToken.id == token_id,
                AccessToken.account_id == account.id,
                AccessToken.type == AccessTokenType.api
            )
        )
    )).scalars().one_or_none():
        await session.delete(token)
        await session.commit()
    return StatusMessage(
        status=status.HTTP_200_OK,
        severity=AlertSeverityEnum.success,
        message="Access token deleted successfully."
    )
