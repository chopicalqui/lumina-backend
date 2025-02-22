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

import logging
from fastapi import Request, status
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from routers.account.token import get_account_by_token
from routers.auth import delete_session_cookie
from . import create_fastapi_app
from core.utils import AuthenticationError, AuthorizationError, StatusMessage, LuminaError
from core.utils.status import AlertSeverityEnum
from core.utils.logging import InjectingFilter
from core.models.account import Account
from core.database import async_session
from utils.auth import OAuth2PasswordBearerWithCookie
from utils.errors.authentication_errors import AuthenticationErrorSkipLogging

prod_app = create_fastapi_app(True)
test_app = create_fastapi_app(False)


async def get_account_by_request(request: Request) -> Account | None:
    """
    Returns the account object by extracting and verifying the access token provided in the request.
    """
    result = None
    try:
        async with async_session() as session:
            token = OAuth2PasswordBearerWithCookie.get_session_token(request)
            result, _ = await get_account_by_token(session, token)
    except Exception:
        ...
    return result


async def get_logging(request: Request) -> logging.Logger:
    """
    Initializes the logger for exception handling.
    """
    result = logging.getLogger(__name__)
    try:
        account = await get_account_by_request(request)
        result.addFilter(InjectingFilter(account, request))
    except Exception:
        ...
    return result


@prod_app.exception_handler(AuthenticationErrorSkipLogging)
@test_app.exception_handler(AuthenticationErrorSkipLogging)
async def handle_skip_logging_errors(request: Request, exc: Exception):
    """
    This function handles all exceptions of type AuthenticationErrorSkipLogging.
    """
    # Log the exception together with the account information.
    logger = await get_logging(request)
    logger.info(str(exc))
    # Prepare the response.
    response = RedirectResponse("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    delete_session_cookie(response)
    content = StatusMessage(
        status=status.HTTP_401_UNAUTHORIZED,
        severity=AlertSeverityEnum.error,
        message="You are not authenticated.",
    ).model_dump()
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=content
    )


@prod_app.exception_handler(AuthorizationError)
@test_app.exception_handler(AuthorizationError)
@prod_app.exception_handler(AuthenticationError)
@test_app.exception_handler(AuthenticationError)
async def handle_authentication_errors(request: Request, exc: Exception):
    """
    This function handles all exceptions of type AuthenticationError.
    """
    # Log the exception together with the account information.
    logger = await get_logging(request)
    logger.exception(exc)
    # Prepare the response.
    response = RedirectResponse("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    delete_session_cookie(response)
    content = StatusMessage(
        status=status.HTTP_401_UNAUTHORIZED,
        severity=AlertSeverityEnum.error,
        message="You are not authenticated.",
    ).model_dump()
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=content
    )


@prod_app.exception_handler(LuminaError)
@test_app.exception_handler(LuminaError)
async def handle_lumina_errors(request: Request, exc: Exception):
    """
    This function handles all generic Lumina exceptions.
    """
    # Log the exception together with the account information.
    logger = await get_logging(request)
    logger.exception(exc)
    # Prepare the response.
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=StatusMessage(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            severity=AlertSeverityEnum.error,
            message=str(exc),
        ).dict()
    )


@prod_app.exception_handler(Exception)
@test_app.exception_handler(Exception)
@prod_app.exception_handler(StarletteHTTPException)
@test_app.exception_handler(StarletteHTTPException)
async def handle_default_errors(request: Request, exc: Exception):
    """
    This is the fallback exception handler for HTTP-related exceptions.
    """
    # Log the exception together with the account information.
    logger = await get_logging(request)
    logger.exception(exc)
    # Prepare the response.
    # response = RedirectResponse("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    # response.delete_cookie(COOKIE_NAME)
    # response.delete_cookie(CSRF_COOKIE_NAME)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=StatusMessage(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            severity=AlertSeverityEnum.error,
            message="An unknown error occurred.",
        ).dict()
    )
