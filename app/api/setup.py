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
from fastapi import status
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from core.utils.status import AlertSeverityEnum
from . import create_fastapi_app
from core.utils import AuthenticationError, AuthorizationError, StatusMessage
from utils.config import COOKIE_NAME, CSRF_COOKIE_NAME

prod_app = create_fastapi_app(True)
test_app = create_fastapi_app(False)
logger = logging.getLogger("guardian")


@prod_app.exception_handler(AuthorizationError)
@test_app.exception_handler(AuthorizationError)
@prod_app.exception_handler(AuthenticationError)
@test_app.exception_handler(AuthenticationError)
def handle_authentication_errors(_request, _exc):
    """
    This function handles all exceptions of type AuthenticationError.
    """
    response = RedirectResponse("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.delete_cookie(COOKIE_NAME)
    response.delete_cookie(CSRF_COOKIE_NAME)
    content = StatusMessage(
        status=status.HTTP_401_UNAUTHORIZED,
        severity=AlertSeverityEnum.info,
        message="You are not authenticated.",
    ).model_dump()
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=content
    )


@prod_app.exception_handler(StarletteHTTPException)
@test_app.exception_handler(StarletteHTTPException)
def handle_authentication_errors(_request, _exc):
    """
    This is the fallback exception handler.
    """
    # response = RedirectResponse("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    # response.delete_cookie(COOKIE_NAME)
    # response.delete_cookie(CSRF_COOKIE_NAME)
    logger.exception(_exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=StatusMessage(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            severity=AlertSeverityEnum.error,
            message="An unknown error occurred.",
        ).dict()
    )
