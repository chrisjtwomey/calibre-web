#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  This file is part of the Calibre-Web (https://github.com/janeczku/calibre-web)
#    Copyright (C) 2018-2019 shavitmichael, OzzieIsaacs
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.


"""API Key Authentication Module
This module provides functionality for managing API keys for user authentication.
"""

import base64
from binascii import hexlify
from os import urandom
from functools import wraps

from flask import g, Blueprint, abort, jsonify
from .cw_login import current_user
from flask_babel import gettext as _

from . import logger, config, ub
from .render_template import render_title_template
from .usermanagement import user_login_required


log = logger.create()

apikey_auth = Blueprint("apikey_auth", __name__, url_prefix="/apikey_auth")


@apikey_auth.route("/ajax/regenerate_api_key", methods=["POST"])
@user_login_required
def regenerate_api_key():
    """Regenerate the API key for the user."""
    if not config.config_allow_api_key_login:
        abort(403, description=_("API key authentication is disabled."))

    if not current_user.is_authenticated:
        abort(403, description=_("You must be logged in to regenerate your API key."))

    # base64 encode a random 48-byte string
    new_api_key = generate_api_key()

    current_user.api_key = new_api_key
    ub.session.commit()

    log.info(f"User {current_user.id} regenerated API key.")
    return jsonify(
        success=True,
        message=_("API key regenerated successfully."),
        api_key=new_api_key
    )

def generate_api_key():
    return base64.b64encode(urandom(48)).decode('utf-8')
