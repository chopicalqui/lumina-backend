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

import asyncio
from fastapi import FastAPI
from contextlib import asynccontextmanager

from core.utils.setup import init_db
from routers import add_routes, CustomHeaderMiddleware
from routers.websockets import notify_account_listener


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    This context manager is used to execute code before and after the FastAPI application is started.
    """
    # Startup events
    # Start listening to account notifications
    # task = asyncio.create_task(notify_account_listener())
    # Initialize the database
    await init_db()
    yield
    # Shutdown events
    # task.cancel()


def create_fastapi_app(prod: bool):
    """
    This function creates a FastAPI application.
    """
    app = FastAPI(
        title="Lumina API" if prod else "Lumina API Test",
        lifespan=lifespan,
        openapi_url=None if prod else "/openapi.json",
        docs_url=None if prod else "/docs",
        redoc_url=None if prod else "/redoc"
    )
    add_routes(app)
    app.add_middleware(CustomHeaderMiddleware)
    return app
