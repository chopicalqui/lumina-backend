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

import sqlalchemy as sa
from uuid import UUID
from fastapi import Depends, Security, APIRouter, Query, status
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.models.account import Account
from core.models.account.role import ApiPermissionEnum
from core.models.account.mui_data_grid import MuiDataGrid, MuiDataGridRead, TableConfig
from core.utils.status import StatusMessage, AlertSeverityEnum
from .account import SUCCESS_MESSAGE, API_ME_SETTINGS, get_current_account


API_DATA_GRID_SUFFIX = "/data-grid"
API_DATA_GRID_PREFIX = API_ME_SETTINGS + API_DATA_GRID_SUFFIX

router = APIRouter(
    prefix=API_DATA_GRID_PREFIX,
    tags=["account", "data-grid"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Incomplete or invalid data"},
        404: {"description": "Not found"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get("/{data_grid_id}", response_model=MuiDataGridRead)
async def read_account_datagrid_settings(
    data_grid_id: UUID,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name])
):
    """
    Allows users to obtain a specific MUI DataGrid configuration.
    """
    result = (await session.execute(
        select(MuiDataGrid).filter(
            sa.and_(
                MuiDataGrid.account_id == account.id,
                MuiDataGrid.settings_id == data_grid_id
            )
        )
    )).scalars().one_or_none()
    return result or MuiDataGridRead(
        settings={}
    )


@router.put("/{data_grid_id}/reset", response_model=StatusMessage)
async def reset_account_datagrid_settings(
    data_grid_id: UUID,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name]),
):
    """
    Allows users to reset a specific MUI DataGrid configuration.
    """
    if result := (await session.execute(
        select(MuiDataGrid).filter(
            sa.and_(
                MuiDataGrid.account_id == account.id,
                MuiDataGrid.settings_id == data_grid_id
            )
        )
    )).scalars().one_or_none():
        result.settings = None
        result.selected_filter_id = None
        await session.commit()
    return StatusMessage(
        status=status.HTTP_200_OK,
        message="DataGrid settings successfully reset. You need to reload the page to see the changes.",
        severity=AlertSeverityEnum.success
    )


@router.put("/{data_grid_id}/config", response_model=StatusMessage)
async def update_user_datagrid_settings(
    data_grid_id: UUID,
    setting: TableConfig,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to update a specific MUI DataGrid configuration (excl. filters).
    """
    # Make sure preference panels are not stored. This ensures that any DataGrid dialogs are not constantly open.
    if result := (await session.execute(
            select(MuiDataGrid).filter(
                sa.and_(
                    MuiDataGrid.account_id == account.id,
                    MuiDataGrid.settings_id == data_grid_id
                )
            )
    )).scalar_one_or_none():
        # If a filter is selected and the current DataGrid configuration update contains an updated filter,
        # then we unselect the filter.
        if setting.filter != result.selected_filter:
            result.selected_filter = None
        result.settings = setting.dict()
    else:
        result = await session.get(Account, account.id)
        session.add(MuiDataGrid(settings_id=data_grid_id, settings=setting.dict(), account=result))
    await session.commit()
    return StatusMessage(
        status=status.HTTP_200_OK,
        message=SUCCESS_MESSAGE,
        severity=AlertSeverityEnum.success
    )


@router.put("/{data_grid_id}", response_model=StatusMessage)
async def update_user_datagrid_settings(
    data_grid_id: UUID,
    setting: TableConfig,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name]),
    filter: bool = Query(default=False, description="Defines whether the selected filter should be reset or not."),
):
    """
    Allows users to update a specific MUI DataGrid configuration (excl. filters).
    """
    # Make sure preference panels are not stored. This ensures that any DataGrid dialogs are not constantly open.
    if result := (await session.execute(
            select(MuiDataGrid).filter(
                sa.and_(
                    MuiDataGrid.account_id == account.id,
                    MuiDataGrid.settings_id == data_grid_id
                )
            )
    )).scalar_one_or_none():
        # If a filter is selected and the current DataGrid configuration update contains an updated filter,
        # then we unselect the filter.
        if filter and setting.filter != result.selected_filter:
            result.selected_filter = None
        result.settings = setting.dict()
    else:
        result = await session.get(Account, account.id)
        session.add(MuiDataGrid(settings_id=data_grid_id, settings=setting.dict(), account=result))
    await session.commit()
    return StatusMessage(
        status=status.HTTP_200_OK,
        message=SUCCESS_MESSAGE,
        severity=AlertSeverityEnum.success
    )
