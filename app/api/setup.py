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

from fastapi import status
from fastapi.responses import RedirectResponse
from . import create_fastapi_app
from core.utils import AuthenticationError
from utils.config import COOKIE_NAME

prod_app = create_fastapi_app(True)
test_app = create_fastapi_app(False)


@prod_app.exception_handler(AuthenticationError)
@test_app.exception_handler(AuthenticationError)
def handle_authentication_errors(_request, _exc):
    """
    This function handles all exceptions of type AuthenticationError.
    """
    response = RedirectResponse("/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.delete_cookie(COOKIE_NAME)
    return response
