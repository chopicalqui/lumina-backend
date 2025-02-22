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
import logging
from pathlib import Path
from dotenv import load_dotenv

from core.utils.logging import log_format, log_date_format

# We load the environment variables from the .env files.
APP_DIRECTORY = Path(__file__).parent.parent.parent.parent / "envs"
if not os.path.isdir(APP_DIRECTORY):
    raise FileNotFoundError("Environment directory not found.")
load_dotenv(APP_DIRECTORY / ".env.backend")
load_dotenv(APP_DIRECTORY / ".env.backend.core")
load_dotenv(APP_DIRECTORY / ".env.redis")

from api.setup import prod_app as app, test_app as test


for handler in logging.root.handlers:
    handler.setFormatter(logging.Formatter(log_format, datefmt=log_date_format))


def main():
    """
    Run this module as a script. This is only useful for debugging purposes.
    """
    import uvicorn
    uvicorn.run("main:test", reload=True, port=8090, host="127.0.0.1")


if __name__ == "__main__":
    main()
