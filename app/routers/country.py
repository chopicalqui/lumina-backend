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

import uuid
from typing import List
from fastapi import Body, Response, Depends, Security, APIRouter, status
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from utils.config import API_PREFIX
from core.utils import NotFoundError
from core.utils.status import StatusMessage, AlertSeverityEnum
from core.database import get_db
from core.models.account import Account
from core.models.account.role import ApiPermissionEnum
from core.models.country import Country, CountryRead, CountryLookup, CountryUpdate
from routers.account import get_current_account

API_COUNTRY_SUFFIX = "/countries"
API_COUNTRY_FLAG_SUFFIX = "/svg/{country_code}"
API_COUNTRY_PREFIX = API_PREFIX + API_COUNTRY_SUFFIX


router = APIRouter(
    prefix=API_COUNTRY_PREFIX,
    tags=["country"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Incomplete or invalid data"},
        404: {"description": "Not found"},
        500: {"description": "Internal Server Error"}
    }
)


@router.get("/lookup", response_model=List[CountryLookup])
async def read_countries(
        session: AsyncSession = Depends(get_db),
        _: Account = Security(get_current_account, scopes=[ApiPermissionEnum.country_read.name])
):
    """
    Returns all country information.
    """
    return (await session.scalars(
        select(Country).where(Country.display).order_by(Country.default, Country.name)
    )).all()


@router.get("", response_model=List[CountryRead])
async def read_countries(
        session: AsyncSession = Depends(get_db),
        _: Account = Security(get_current_account, scopes=[ApiPermissionEnum.country_read.name])
):
    """
    Returns all country information.
    """
    return (await session.scalars(
        select(Country).where(Country.display).order_by(Country.default, Country.name)
    )).all()


@router.put("", response_model=StatusMessage)
async def read_countries(
        session: AsyncSession = Depends(get_db),
        body: CountryUpdate = Body(...),
        _: Account = Security(get_current_account, scopes=[ApiPermissionEnum.country_read.name])
):
    """
    Returns all country information.
    """
    if result := (await session.scalars(
        select(Country).where(Country.id == body.id).order_by(Country.default, Country.name)
    )).all():
        result.default = body.default
        result.display = body.display
    return StatusMessage(
                status=status.HTTP_200_OK,
                severity=AlertSeverityEnum.success,
                message="Country successfully updated.",
            )


@router.get("/{country_id}", response_model=CountryRead)
async def read_country(
        country_id: uuid.UUID,
        session: AsyncSession = Depends(get_db),
        _: Account = Security(get_current_account, scopes=[ApiPermissionEnum.country_read.name])
):
    """
    Returns all country information.
    """
    result = await session.get(Country, country_id)
    if not result:
        raise NotFoundError("Country not found")
    return result


@router.get(API_COUNTRY_FLAG_SUFFIX)
async def read_country_flag(
        country_code: str,
        session: AsyncSession = Depends(get_db),
        _: Account = Security(get_current_account, scopes=[ApiPermissionEnum.country_read.name])
):
    """
    Returns flag by its country code.
    """
    if not (country := (await session.scalars(
            select(Country).filter_by(code=country_code.upper())
    )).one_or_none()):
        raise NotFoundError("Country not found")
    return Response(content=country.svg_image, media_type="image/svg+xml")
