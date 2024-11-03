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

import os
from pathlib import Path
from dotenv import load_dotenv

# We load the environment variables from the .env files.
APP_DIRECTORY = Path(__file__).parent.parent.parent.parent / "envs"
if not os.path.isdir(APP_DIRECTORY):
    raise FileNotFoundError("Environment directory not found.")
load_dotenv(APP_DIRECTORY / ".env.backend")
load_dotenv(APP_DIRECTORY / ".env.backend.core")
load_dotenv(APP_DIRECTORY / ".env.redis")

from fastapi import FastAPI
from contextlib import asynccontextmanager
from routers import add_routes, CustomHeaderMiddleware
from core.setup import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    This context manager is used to execute code before and after the FastAPI application is started.
    """
    # Startup events
    # Start listening to user notifications
    # task = asyncio.create_task(notify_user_listener())
    # Initialize the database
    await init_db(drop_tables=True, create_tables=True, load_data=True)
    yield
    # Shutdown events
    # task.cancel()


app = FastAPI(
    title="Lumina API",
    lifespan=lifespan,
    openapi_url=None,
    docs_url=None,
    redoc_url=None
)
add_routes(app)
app.add_middleware(CustomHeaderMiddleware)

test = FastAPI(
    title="Lumina API",
    lifespan=lifespan
)
add_routes(test)
test.add_middleware(CustomHeaderMiddleware)


def main():
    """
    Run this module as a script. This is only useful for debugging purposes.
    """
    import uvicorn
    uvicorn.run("main:test", reload=True, port=8090, host="127.0.0.1")


if __name__ == "__main__":
    main()
