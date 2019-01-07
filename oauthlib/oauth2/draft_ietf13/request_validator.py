# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.draft_ietf13.request_validator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import absolute_import, unicode_literals

from oauthlib.oauth2.rfc6749.request_validator import RequestValidator as OAuth2RequestValidator

import logging

log = logging.getLogger(__name__)

class RequestValidator(OAuth2RequestValidator):

    def get_verification_url(self, request):
        """Get the verification URI for the client.
        
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_verification_url_complete(self, request, user_code):
        """Get the complete verification URI for the client.
        
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param code: Unicode user code
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_interval(self, request):
        """Get the polling interval URI for the client.
        
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        return 5

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
