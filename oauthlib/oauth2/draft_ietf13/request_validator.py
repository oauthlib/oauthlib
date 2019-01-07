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

    def get_verification_url(self):
        pass
        
    def get_verification_url_complete(self):
        pass
        
    def get_interval(self):
        pass
        
    def save_device_code(self):
        pass
        
    def validate_device_code(self):
        pass
        
    def validate_user_code(self):
        pass
        
    def update_user_code_authorization_status(self):
        pass
        
    def invalidate_device_code(self):
        pass
        