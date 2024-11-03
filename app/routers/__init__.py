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

from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from util.config import API_PREFIX


class CustomHeaderMiddleware(BaseHTTPMiddleware):
    """
    This middleware is used to add custom headers to the response.
    """
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Referrer-Policy'] = 'no-referrer'
        # response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        if request.url.path.startswith(API_PREFIX + "/countries/svg"):
            # Cache images for one day
            response.headers['Cache-Control'] = 'public, max-age=86400'
        else:
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Pragma'] = 'no-cache'
        return response


def add_routes(app):
    """
    This method can be used to add all routes to the given FastAPI app.
    :param app: FastAPI app
    """
    ...