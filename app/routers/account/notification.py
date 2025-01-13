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
from typing import Callable, Awaitable, List
from fastapi import Depends, Security, APIRouter, status
from core.database import get_db
from core.models.account import Account
from core.models.account.notification import Notification, NotificationRead
from core.models.account.role import ApiPermissionEnum
from core.utils.status import StatusMessage, AlertSeverityEnum
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from . import API_ME_SUFFIX, get_current_account

router = APIRouter(
    prefix=API_ME_SUFFIX + "/notifications",
    tags=["account"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Incomplete or invalid data"},
        404: {"description": "Not found"},
        500: {"description": "Internal Server Error"}
    }
)


async def process_account_notification(
        account: Account,
        notification_id: UUID,
        session: AsyncSession,
        process_fn: Callable[[Notification, AsyncSession], Awaitable[None]]
) -> None:
    """
    Processes an account notification using the provided process_fn callable.
    """
    if result := (await session.execute(
            select(Notification).filter(
                sa.and_(
                    Notification.account_id == account.id,
                    Notification.id == notification_id
                )
            )
    )).scalars().one_or_none():
        await process_fn(result, session)


@router.get("", response_model=List[NotificationRead])
async def get_account_notifications(
        session: AsyncSession = Depends(get_db),
        account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name])
):
    """
    Allows accounts to obtain their notifications.
    """
    result = (await session.execute(
        select(Notification).filter(
            sa.and_(
                Notification.account_id == account.id
            )
        )
    )).scalars().all()
    return result if result else []


@router.delete("/{notification_id}", response_model=StatusMessage)
async def delete_account_notifications(
        notification_id: UUID,
        session: AsyncSession = Depends(get_db),
        account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows accounts to delete their notifications.
    """
    async def delete_notification(notification: Notification, session: AsyncSession):
        await session.delete(notification)
        await session.commit()
    await process_account_notification(account, notification_id, session, delete_notification)
    return StatusMessage(
        status=status.HTTP_200_OK,
        severity=AlertSeverityEnum.success,
        message=f"Notification successfully deleted."
    )


@router.put("/{notification_id}/toggle-read", response_model=StatusMessage)
async def get_account_notifications(
        notification_id: UUID,
        session: AsyncSession = Depends(get_db),
        account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows accounts to mark their notifications as read/unread.
    """
    async def toggle_notification_read(notification: Notification, session: AsyncSession):
        notification.read = not notification.read
        await session.commit()
    await process_account_notification(account, notification_id, session, toggle_notification_read)
    return StatusMessage(
        status=status.HTTP_200_OK,
        severity=AlertSeverityEnum.success,
        message=f"Notification successfully updated."
    )
