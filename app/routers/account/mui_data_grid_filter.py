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
from typing import List
from fastapi import Depends, Security, APIRouter, status
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.models.account import Account
from core.models.account.role import ApiPermissionEnum
from core.models.account.mui_data_grid import MuiDataGrid, MuiDataGridFilter
from core.models.account.mui_data_grid_filter import (
    MuiDataGridFilterLookup, MuiDataGridFilterCreate, MuiDataGridFilterUpdate, Filter
)
from core.utils.status import StatusMessage, AlertSeverityEnum
from core.utils import NotFoundError
from .account import get_current_account
from .mui_data_grid import API_DATA_GRID_PREFIX


API_DATA_GRID_FILTER_MENU_SUFFIX = "/filter-menu"
API_DATA_GRID_FILTER_MENU_SELECTED_SUFFIX = "/selected"
API_DATA_GRID_FILTER_MENU_PREFIX = API_DATA_GRID_PREFIX + "/{data_grid_id}" + API_DATA_GRID_FILTER_MENU_SUFFIX

router = APIRouter(
    prefix=API_DATA_GRID_FILTER_MENU_PREFIX,
    tags=["account", "data-grid"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Incomplete or invalid data"},
        404: {"description": "Not found"},
        500: {"description": "Internal Server Error"}
    }
)


def _update_selected_filter(data_grid: MuiDataGrid, new_filter: MuiDataGridFilter):
    """
    Update the filter of a MUI DataGrid.
    """
    settings = dict(data_grid.settings or {})
    settings["filter"] = Filter(filterModel=new_filter.filter).dict()
    if new_filter.id is not None:
        data_grid.selected_filter_id = new_filter.id
    else:
        data_grid.selected_filter = new_filter
    if not data_grid.settings:
        data_grid.settings = {}
    data_grid.settings = settings


@router.get("", response_model=List[MuiDataGridFilterLookup])
async def read_data_grid_filters(
    data_grid_id: UUID,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name])
):
    """
    Allows users to obtain their MUI DataGrid filters.
    """
    result = (await session.execute(
        select(MuiDataGridFilter)
        .join(MuiDataGrid, onclause=MuiDataGridFilter.data_grid_id == MuiDataGrid.id)
        .filter(
            sa.and_(
                MuiDataGrid.account_id == account.id,
                MuiDataGrid.settings_id == data_grid_id
            )
        )
    )).scalars().all()
    return result


@router.post("", response_model=MuiDataGridFilterLookup)
async def create_data_grid_filter(
    data_grid_id: UUID,
    body: MuiDataGridFilterCreate,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to create new DataGrid filters.
    """
    if not (data_grid := (await session.execute(
        select(MuiDataGrid)
        .filter(
            sa.and_(
                MuiDataGrid.account_id == account.id,
                MuiDataGrid.settings_id == data_grid_id
            )
        )
    )).scalar_one_or_none()):
        # We don't create a DataGrid table record here because if the DataGrid does not exist yet, then this means that
        # also no filter was set yet.
        raise NotFoundError("DataGrid not found.")
    # We create the new filter
    result = MuiDataGridFilter(
        name=body.name,
        filter=body.filter.dict(),
        data_grid_id=data_grid.id
    )
    session.add(result)
    # Update the filter settings in the DataGrid using the selected filter
    _update_selected_filter(data_grid, result)
    await session.commit()
    await session.refresh(result)
    return result


@router.get(API_DATA_GRID_FILTER_MENU_SELECTED_SUFFIX, response_model=MuiDataGridFilterLookup | None)
async def read_account_datagrid_selected_menu_item(
    data_grid_id: UUID,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name])
):
    """
    Allows users to obtain the selected filter menu item for a specific DataGrid.
    """
    result = (await session.scalars(
        select(MuiDataGrid).filter(
            sa.and_(
                MuiDataGrid.account_id == account.id,
                MuiDataGrid.settings_id == data_grid_id
            )
        )
    )).one_or_none()
    return result.selected_filter if result else None


@router.put(API_DATA_GRID_FILTER_MENU_SELECTED_SUFFIX, response_model=StatusMessage)
async def update_data_grid_filter(
    data_grid_id: UUID,
    body: MuiDataGridFilterUpdate,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows a user to update the selected filter in a MUI DataGrid.
    """
    if result := (await session.execute(
        select(MuiDataGrid, MuiDataGridFilter)
        .outerjoin(
            MuiDataGridFilter,
            onclause=sa.and_(MuiDataGridFilter.data_grid_id == MuiDataGrid.id,
                             MuiDataGridFilter.id == body.selected_filter_id)
        )
        .filter(
            sa.and_(
                MuiDataGrid.account_id == account.id,
                MuiDataGrid.settings_id == data_grid_id
            )
        )
    )).one_or_none():
        data_grid, selected_filter = result
        if selected_filter is None:
            # If the selected filter is set to None, then we remove the filter from the DataGrid.
            data_grid.selected_filter = None
            data_grid.settings = None
        else:
            # Update the filter settings in the DataGrid using the selected filter
            _update_selected_filter(data_grid, selected_filter)
            session.add(data_grid)
        await session.commit()
    return StatusMessage(
        status=status.HTTP_200_OK,
        message="DataGrid filter successfully updated.",
        severity=AlertSeverityEnum.success
    )


@router.delete("/{selected_filter_id}", response_model=StatusMessage)
async def delete_data_grid_filter(
    data_grid_id: UUID,
    selected_filter_id: UUID,
    session: AsyncSession = Depends(get_db),
    account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows users to delete DataGrid filters.
    """
    if result := (await session.execute(
        select(MuiDataGridFilter)
        .outerjoin(
            MuiDataGrid,
            onclause=MuiDataGridFilter.data_grid_id == MuiDataGrid.id
        )
        .filter(
            sa.and_(
                MuiDataGrid.account_id == account.id,
                MuiDataGrid.settings_id == data_grid_id,
                MuiDataGridFilter.id == selected_filter_id
            )
        )
    )).scalar_one_or_none():
        await session.delete(result)
        await session.commit()
    return StatusMessage(
        status=status.HTTP_200_OK,
        message="DataGrid filter successfully deleted.",
        severity=AlertSeverityEnum.success
    )
