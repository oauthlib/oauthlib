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

    def save_device_code(self, client_id, device_code, request):
        """Persist the device_code.

        The code should at minimum be stored with:
            - the client_id (client_id)
            - the redirect URI used (request.redirect_uri)
            - a resource owner / user (request.user)
            - the authorized scopes (request.scopes)
            - the expiry date

        The 'code' argument is actually a dictionary, containing at least a
        'user_code', 'device_code' and 'expires_in' key with the actual authorization code:

        {
            'device_code': 'sdf345jsdf0934f',
            'user_code': 'ADFG-GHJK',
            'expires_in': 54353
        }

        :param client_id: Unicode client identifier.
        :param device_code: A dict of the authorization code grant and, optionally, state.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        raise NotImplementedError('Subclasses must implement this method.')


    def validate_device_code(self):
        """Verify that the authorization_code is valid and assigned to the given
        client.

        Before returning true, set the following based on the information stored
        with the code in 'save_authorization_code':

            - request.user
            - request.state (if given)
            - request.scopes
            - request.claims (if given)
        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes
        must also be set.

        The request.claims property, if it was given, should assigned a dict.

        :param client_id: Unicode client identifier.
        :param code: Unicode authorization code.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')


    def validate_user_code(self, client_id, device_code, request):
        """Verify that the authorization_code is valid and assigned to the given
        client.

        Before returning true, set the following based on the information stored
        with the code in 'save_authorization_code':

            - request.user
            - request.state (if given)
            - request.scopes
            - request.claims (if given)
        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes
        must also be set.

        The request.claims property, if it was given, should assigned a dict.

        :param client_id: Unicode client identifier.
        :param code: Unicode authorization code.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')


    def update_user_code_authorization_status(self):
        """Verify that the authorization_code is valid and assigned to the given
        client.

        Before returning true, set the following based on the information stored
        with the code in 'save_authorization_code':

            - request.user
            - request.state (if given)
            - request.scopes
            - request.claims (if given)
        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes
        must also be set.

        The request.claims property, if it was given, should assigned a dict.

        :param client_id: Unicode client identifier.
        :param code: Unicode authorization code.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')


    def invalidate_device_code(self, client_id, device_code, request):
        """Invalidate an device code after use.

        :param client_id: Unicode client identifier.
        :param device_code: The device code grant (request.device_code).
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        raise NotImplementedError('Subclasses must implement this method.')

