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

from typing import List
from fastapi import Body, Depends, Response, Header, Security, APIRouter, UploadFile, File, status, Request
from sqlalchemy import and_
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from .account import API_ME, get_current_account
from core.models.account import (
    Account, AccountReadMe, ApiPermissionEnum, AccessToken, AccessTokenRead, AccessTokenType
)
from core.database import get_db, update_database_record

API_ME_ACCESS_TOKEN = API_ME + "/access-tokens"


router = APIRouter(
    prefix=API_ME_ACCESS_TOKEN,
    tags=["access token"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Incomplete or invalid data"},
        404: {"description": "Not found"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get("", response_model=List[AccessTokenRead])
async def read_my_access_tokens(
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name]),
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
