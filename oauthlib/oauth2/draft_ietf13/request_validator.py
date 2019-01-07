# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.draft_ietf13.request_validator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import absolute_import, unicode_literals

from oauthlib.oauth2.rfc6749.request_validator import RequestValidator

import logging

log = logging.getLogger(__name__)

class RequestValidator(RequestValidator):
    pass

    # get_verification_url
    # get_verification_url_complete
    # get_interval
    # save_device_code
    # validate_device_code
    # validate_user_code
    # update_user_code_authorization_status
    # invalidate_device_code