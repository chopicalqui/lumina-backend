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

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"

import json
import asyncio
import logging
from typing import Dict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from routers.account.token import verify_token
from core.database import settings_base as settings
from core.utils.websockets import manager, WebSocketWrapper
from core.models.account import WebSocketNotifyAccount as NotifyAccount
from core.database import get_db
from core.database.redis_client import subscribe
from utils.config import COOKIE_NAME

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/ws",
    tags=["websocket"]
)


async def notify_account_listener():
    """
    Listens to the Redis queue and sends notifications to the accounts via WebSockets
    """
    try:
        async def send_notification(message: Dict | str):
            try:
                json_object = message if isinstance(message, dict) else json.loads(message)
                notify = NotifyAccount(**json_object)
                await manager.send(notify=notify)
            except Exception as e:
                logger.exception(e)
        await subscribe(
            username=settings.redis_user,
            password=settings.redis_password,
            channel=settings.redis_notify_user_channel,
            callback=send_notification
        )
        logger.debug("Redis monitor for WebSocket manager successfully started.")
    except Exception as ex:
        logger.exception(ex)


def start_notify_account_listener():
    """
    Starts the listener for notifying accounts via WebSockets.
    """
    asyncio.create_task(notify_account_listener())


async def listen_to_messages(websocket: WebSocketWrapper):
    """
    Listens to the messages from the WebSocket.
    """
    while True:
        try:
            await websocket.receive_json()
        except WebSocketDisconnect:
            break
        except Exception as e:
            logger.exception(e)
            break


@router.websocket("")
async def websocket_endpoint(
    websocket: WebSocket,
    session: AsyncSession = Depends(get_db),
):
    """
    Websocket endpoint.
    """
    session_cookie = websocket.cookies.get(COOKIE_NAME, "")
    x_real_ip = [item.strip() for item in websocket.headers.get("x-real-ip", "").split(",")]
    # 1. We verify the access token and user access
    account, payload, access_token = await verify_token(
        session=session,
        token=session_cookie,
        _x_real_ip=x_real_ip,
        request=websocket
    )
    wrapper = WebSocketWrapper(
        account=account,
        websocket=websocket,
        token=access_token.checksum
    )
    await manager.connect(websocket=wrapper, account=account)
    # Start listening in a background task
    task = asyncio.create_task(listen_to_messages(wrapper))
    try:
        await task
    finally:
        await manager.disconnect(account_id=account.id)
