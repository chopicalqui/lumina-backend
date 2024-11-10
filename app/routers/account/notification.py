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
from typing import Callable, Awaitable, List
from fastapi import Depends, Security, APIRouter, status
from core.database import get_db
from core.models.account import Account
from core.models.account.notification import Notification, NotificationRead
from core.models.account.role import ApiPermissionEnum
from core.utils.status import StatusMessage, AlertSeverityEnum
from sqlalchemy import delete, update
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
        process_fn: Callable[[UUID, AsyncSession], Awaitable[None]]
):
    """
    Processes an account notification.
    """
    notification = await session.get(Notification, notification_id)
    if notification and notification.account_id == account.id:
        process_fn(notification_id, session)
    return account.notifications


@router.get("", response_model=List[NotificationRead])
def get_account_notifications(
        account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_read.name])
):
    """
    Allows accounts to obtain their notifications.
    """
    return account.notifications


@router.delete("/{notification_id}", response_model=StatusMessage)
async def delete_account_notifications(
        notification_id: UUID,
        session: AsyncSession = Depends(get_db),
        account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Allows accounts to delete their notifications.
    """
    async def delete_notification(notification_id: UUID, session: AsyncSession):
        await session.execute(
            delete(Notification).where(Notification.id == notification_id)
        )
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
    async def toggle_notification_read(notification_id: UUID, session: AsyncSession):
        await session.execute(
            update(Notification).where(Notification.id == notification_id).values(read=not Notification.read)
        )
        await session.commit()
    await process_account_notification(account, notification_id, session, toggle_notification_read)
    return StatusMessage(
        status=status.HTTP_200_OK,
        severity=AlertSeverityEnum.success,
        message=f"Notification successfully updated."
    )
