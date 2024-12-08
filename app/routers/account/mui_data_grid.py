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
from typing import Dict
from fastapi import Depends, Security, APIRouter, status
from sqlalchemy.ext.asyncio import AsyncSession
from core.utils.logging import get_logger
from core.database import get_db
from core.models.account import Account
from core.models.account.role import ApiPermissionEnum
from core.models.account.mui_data_grid import MuiDataGrid
from core.utils.status import StatusMessage, AlertSeverityEnum
from .account import SUCCESS_MESSAGE, FAILED_MESSAGE, API_ME_SETTINGS, get_current_account


API_DATA_GRID_SUFFIX = "/data-grid"
API_DATA_GRID_PREFIX = API_ME_SETTINGS + API_DATA_GRID_SUFFIX

router = APIRouter(
    prefix=API_DATA_GRID_PREFIX,
    tags=["account"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Incomplete or invalid data"},
        404: {"description": "Not found"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get("/{guid}", response_model=Dict)
def read_account_datagrid_settings(
    guid: UUID,
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name])
):
    """
    Allows users to obtain a specific MUI DataGrid configuration.
    """
    if not (result := [item for item in account.data_grids if item.settings_id == guid]):
        return {}
    return result[0].settings


@router.put("/{guid}/reset", response_model=StatusMessage)
async def reset_account_datagrid_settings(
    guid: UUID,
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name]),
):
    """
    Allows users to reset a specific MUI DataGrid configuration.
    """
    try:
        result = await session.get(Account, account.id)
        for item in [item for item in result.data_grids if item.settings_id == guid]:
            item.settings = {}
        else:
            await session.commit()
        return StatusMessage(
            status=status.HTTP_200_OK,
            message="DataGrid settings have been reset. You need to reload the page to see the changes.",
            severity=AlertSeverityEnum.success
        )
    except Exception as ex:
        logger.exception(ex)
        return StatusMessage(
            status=status.HTTP_400_BAD_REQUEST,
            message=FAILED_MESSAGE,
            severity=AlertSeverityEnum.error
        )


@router.put("/{guid}", response_model=StatusMessage)
async def update_user_datagrid_settings(
    guid: UUID,
    setting: Dict,  # TODO: Add a Pydantic model for this.
    session: AsyncSession = Depends(get_db),
    logger: logging.Logger = Depends(get_logger),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to update a specific MUI DataGrid configuration.
    """
    try:
        # Make sure preference panels are not stored. This ensures that any DataGrid dialogs are not constantly open.
        if "preferencePanel" in setting:
            del setting["preferencePanel"]
        result = await session.get(Account, account.id)
        if result := [item for item in result.data_grids if item.settings_id == guid]:
            result[0].settings = setting
        else:
            result = await session.get(Account, account.id)
            session.add(MuiDataGrid(settings_id=guid, settings=setting, account=result))
        await session.commit()
        return StatusMessage(
            status=status.HTTP_200_OK,
            message=SUCCESS_MESSAGE,
            severity=AlertSeverityEnum.success
        )
    except Exception as ex:
        logger.exception(ex)
        return StatusMessage(
            status=status.HTTP_400_BAD_REQUEST,
            message=FAILED_MESSAGE,
            severity=AlertSeverityEnum.error
        )
