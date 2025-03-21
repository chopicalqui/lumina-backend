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

import httpx
from logging import Logger
from typing import Union, List
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi import Depends, APIRouter, Security, status
from sqlalchemy import and_, update
from sqlalchemy.ext.asyncio import AsyncSession

from routers.account import get_current_account
from core.utils import AuthenticationError, IdpConnectionError, StatusMessage
from core.utils.logging import get_logger
from utils.config import settings, COOKIE_NAME, CSRF_COOKIE_NAME
from utils.idp import IdentityProviderBase
from utils.idp.factory import IdentityProviderFactory, IdentityProviderNotFound
from core.database import get_db, get_by_id
from core.utils.websockets import manager
from core.models.account import Account, ApiPermissionEnum, AccessToken, AccessTokenType

router = APIRouter(
    prefix="/api",
    tags=["auth"]
)


def add_session_cookie(response: RedirectResponse | JSONResponse, access_token: str, token: str):
    """
    Adds the session cookies to the response.
    """
    response.set_cookie(
        COOKIE_NAME,
        access_token,
        httponly=True,
        secure=settings.https,
        samesite="strict",
        path="/api"
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=False,
        secure=settings.https,
        samesite="strict",
        path="/"
    )


def delete_session_cookie(response: RedirectResponse | JSONResponse):
    """
    Deletes the session cookies from the response.
    """
    response.headers["Clear-Site-Data"] = '"cache", "storage", "clientHints"'
    response.delete_cookie(COOKIE_NAME, path="/api")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")


@router.get("/redirect-login")
async def redirect_login():
    """
    Redirects the account to the OpenID Provider's authorization page.
    """
    # Redirect the account to the OpenID Provider's authorization page
    authorization_url = f"{settings.authorization_url}?response_type=code&client_id={settings.client_id}&redirect_uri={settings.redirect_uri}"
    return RedirectResponse(authorization_url)


@router.get("/callback")
async def callback(
        code: str,
        session: AsyncSession = Depends(get_db),
        logger: Logger = Depends(get_logger),
        x_real_ip: Union[List[str], None] = None
):
    """
    Callback function for the OpenID Connect.
    """
    try:
        # Exchange the authorization code for an access token
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.redirect_uri,
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
        }
        # Verify account
        async with httpx.AsyncClient() as client:
            response = await client.post(settings.token_url, data=data)
        if response.status_code != 200:
            logger.error(f"Could not verify account: {response.text}")
            raise IdpConnectionError()
        provider = IdentityProviderFactory.get(
            settings.idp_type,
            client_ip=x_real_ip[0] if x_real_ip else None,
            response=response
        )
        access_token, token = await provider.get_token(session=session)
        await session.commit()
        # Finally, we create and return the HTTP response.
        response = RedirectResponse("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        add_session_cookie(response, access_token, token.checksum)
        return response
    except Exception as e:
        logger.exception(e)
        if isinstance(e, AuthenticationError):
            message_id = "5f1a9d3a-e95e-4976-9ed8-2308a9b0a2fd"
        elif isinstance(e, IdpConnectionError):
            message_id = "5157ba8a-848e-4907-a7f7-07e9f9385e77"
        elif isinstance(e, IdentityProviderNotFound):
            message_id = "1e46be48-5696-4103-83a2-4f31fd6770f1"
        else:
            message_id = "78fac82f-0f11-458b-aa8a-2e9eecabe819"
        return RedirectResponse(
            "/" + (f"#{message_id}" if message_id else ""),
            status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )


@router.post("/logout")
async def logout(
        session: AsyncSession = Depends(get_db),
        account: Account = Security(get_current_account, scopes=[item.name for item in ApiPermissionEnum])
):
    """
    Invalidates the current token.
    """
    # We revoke the current token.
    await session.execute(
        update(AccessToken).where(
            and_(
                AccessToken.account_id == account.id,
                AccessToken.type == AccessTokenType.user
            )
        ).values(revoked=True)
    )
    await session.commit()
    # We also close all established WebSockets
    await manager.disconnect(account_id=account.id)
    # Create HTTP response
    response = JSONResponse(content=StatusMessage(
        status=status.HTTP_200_OK,
        severity="info",
        message="Logged out."
    ).model_dump())
    delete_session_cookie(response)
    return response


@router.post("/renew")
async def renew(
        session: AsyncSession = Depends(get_db),
        account: Account = Security(get_current_account, scopes=[ApiPermissionEnum.account_me_update.name])
):
    """
    Issues a new session token.
    """
    claim_account = await get_by_id(session, Account, account.id)
    access_token, token = await IdentityProviderBase.create_token_for_account(
        session=session,
        claim_account=claim_account
    )
    await session.commit()
    # Finally, we create and return the HTTP response.
    content = StatusMessage(
        status=status.HTTP_200_OK,
        severity="info",
        message="Session token renewed."
    ).model_dump()
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=content
    )
    add_session_cookie(response, access_token, token.checksum)
    return response
