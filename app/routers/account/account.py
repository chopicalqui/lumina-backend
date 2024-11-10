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

import logging
from uuid import UUID
from typing import Annotated, List
from fastapi import Body, Depends, Response, Header, Security, APIRouter, UploadFile, File, status
from fastapi.security import SecurityScopes
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from utils.auth import oauth2_scheme
from core.utils import NotFoundError, InvalidDataError, AuthenticationError
from core.utils.logging import get_logger
from core.database import get_db, update_database_record
from core.models.file import verify_png_image
from core.models.account import (
    Account, AccountRead, AccountReadMe, AccountUpdateAdmin, TableDensityType
)
from core.models.account.role import ApiPermissionEnum
from core.database import get_by_id
from core.utils.status import StatusMessage, AlertSeverityEnum
from .token import verify_token
from utils.config import API_PREFIX


API_ACCOUNT_SUFFIX = "/accounts"
API_ME_SUFFIX = "/me"
API_ME_SETTINGS_PREFIX = API_ME_SUFFIX + "/settings"
API_ACCOUNT_PREFIX = API_PREFIX + API_ACCOUNT_SUFFIX
API_ME_SUFFIX = API_ACCOUNT_PREFIX + API_ME_SUFFIX
API_ME_SETTINGS_SUFFIX = API_ME_SUFFIX + API_ME_SETTINGS_PREFIX
SUCCESS_MESSAGE = "Account updated successfully."
FAILED_MESSAGE = "Account update failed."

router = APIRouter(
    prefix=API_ACCOUNT_PREFIX,
    tags=["account"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Incomplete or invalid data"},
        404: {"description": "Not found"},
        500: {"description": "Internal Server Error"}
    }
)


async def get_current_account(
    security_scopes: SecurityScopes,
    session_token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    x_real_ip: list[str] | None = Header(default=None)
) -> Account:
    """
    Verifies the given token and returns the account if the token is valid and the account exists.
    """
    user_account, payload = await verify_token(session, logger, x_real_ip, session_token)
    # Check 2: Check whether the token contains one of the required scopes.
    scoping_results = [scope in security_scopes.scopes for scope in payload.get("scopes", [])]
    if not any(scoping_results):
        logger.critical(f"Account {user_account.email} tried to access scopes {security_scopes.scope_str}.")
        raise AuthenticationError(f"Could not validate account: {user_account.email}")
    # Check 3: Check whether the account's IP address has changed.
    # if x_real_ip and x_real_ip[0] != account.client_ip:
    #     logger.warning(f"Account {account.email} tried to access the application from a different IP address.")
    #     session.query(Account).filter_by(id=user_account.id).update({"client_ip": x_real_ip[0]})
    # We checked this already during login and only if the user is active we return the token.
    if not user_account.is_active:
        raise AuthenticationError()
    return user_account


@router.get("/me", response_model=AccountReadMe)
def read_me(
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name]),
    session: AsyncSession = Depends(get_db)
):
    """
    Allows users to obtain their account information.
    """
    return get_by_id(session, Account, account.id)


@router.get("/me/settings/avatar")
async def get_avatar(
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name])
):
    """
    Allows users to request their avatar.
    """
    if not account.avatar:
        return
    return Response(content=account.avatar, media_type="image/png")


@router.put("/me/settings/avatar", response_model=AccountRead)
async def update_my_avatar(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to update their avatar.
    """
    image_data = await verify_png_image(file, max_file_size=1024 ** 2)
    # We cannot query the user and assign the avatar then because this results in an encoding error. As a workaround,
    # we update the avatar directly in the database.
    result = await session.get(Account, account.id)
    result.avatar = image_data
    await session.commit()
    await session.refresh(result)
    return result


@router.put("/me/settings/avatar/reset", response_model=StatusMessage)
async def reset_avatar(
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to reset their avatar.
    """
    try:
        result = await session.get(Account, account.id)
        result.avatar = None
        session.add(result)
        await session.commit()
        return StatusMessage(
            status=status.HTTP_200_OK,
            severity=AlertSeverityEnum.success,
            message=SUCCESS_MESSAGE
        )
    except Exception as ex:
        logger.exception(ex)
        return StatusMessage(
            status=status.HTTP_400_BAD_REQUEST,
            severity=AlertSeverityEnum.error,
            message=FAILED_MESSAGE,
        )


@router.put("/me/settings/toggle-light-mode", response_model=StatusMessage)
async def update_preferred_visual_mode(
    mode: bool,
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to switch between light and dark mode.
    """
    try:
        result = await session.get(Account, account.id)
        result.light_mode = not mode
        session.add(result)
        await session.commit()
        return StatusMessage(
            status=status.HTTP_200_OK,
            severity=AlertSeverityEnum.success,
            message=SUCCESS_MESSAGE
        )
    except Exception as ex:
        logger.exception(ex)
        return StatusMessage(
            status=status.HTTP_400_BAD_REQUEST,
            severity=AlertSeverityEnum.error,
            message=FAILED_MESSAGE,
        )


@router.put("/me/settings/toggle-menu", response_model=StatusMessage)
async def update_toggle_menu_setting(
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to toggle their React sidebar.
    """
    try:
        result = await session.get(Account, account.id)
        result.toggle_menu = not result.toggle_menu
        await session.commit()
        return StatusMessage(
            status=status.HTTP_200_OK,
            severity=AlertSeverityEnum.success,
            message=SUCCESS_MESSAGE
        )
    except Exception as ex:
        logger.exception(ex)
        return StatusMessage(
            status=status.HTTP_400_BAD_REQUEST,
            severity=AlertSeverityEnum.error,
            message=FAILED_MESSAGE,
        )


@router.put("/me/settings/table-density/{density}", response_model=StatusMessage)
async def update_preferred_table_density(
    density: str,
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to update their MUI DataGrid table density.
    """
    try:
        density = TableDensityType[density]
        result = await session.get(Account, account.id)
        result.table_density = density
        await session.commit()
        return StatusMessage(
            status=status.HTTP_200_OK,
            severity=AlertSeverityEnum.success,
            message=f"User settings updated."
        )
    except Exception as ex:
        logger.exception(ex)
        return StatusMessage(
            status=status.HTTP_400_BAD_REQUEST,
            severity=AlertSeverityEnum.error,
            message=FAILED_MESSAGE,
        )


@router.get("", response_model=List[AccountRead])
async def read_accounts(
    session: AsyncSession = Depends(get_db),
    _: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_read.name])
):
    """
    Returns all accounts.
    """
    result = await session.execute(
        select(Account).order_by(Account.full_name)
    )
    return result.scalars().all()


@router.get("/{user_id}", response_model=AccountRead)
async def read_account(
    user_id: UUID,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_read.name]),
):
    """
    Returns an account by its ID.
    """
    result = await session.get(Account, user_id)
    if not result:
        raise NotFoundError("Account not found", account=account)
    return result


@router.put("", response_model=AccountRead)
def update_account(
    item: Annotated[AccountUpdateAdmin, Body],
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    _: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Updates an account.
    """
    try:
        return update_database_record(
            session=session,
            source=item,
            source_model=AccountUpdateAdmin,
            query_model=Account,
            commit=True
        )
    except NotFoundError as e:
        logger.exception(e)
        return item
    except Exception as e:
        raise InvalidDataError(str(e))
