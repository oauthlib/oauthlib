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
        """Persist the authorization_code.

        The code should at minimum be stored with:
            - the client_id (client_id)
            - the redirect URI used (request.redirect_uri)
            - a resource owner / user (request.user)
            - the authorized scopes (request.scopes)
            - the client state, if given (code.get('state'))

        The 'code' argument is actually a dictionary, containing at least a
        'code' key with the actual authorization code:

            {'code': 'sdf345jsdf0934f'}

        It may also have a 'state' key containing a nonce for the client, if it
        chose to send one.  That value should be saved and used in
        'validate_code'.

        It may also have a 'claims' parameter which, when present, will be a dict
        deserialized from JSON as described at
        http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
        This value should be saved in this method and used again in 'validate_code'.

        :param client_id: Unicode client identifier.
        :param code: A dict of the authorization code grant and, optionally, state.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request

        Method is used by:
            - Authorization Code Grant
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


    def validate_user_code(self):
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


    def invalidate_device_code(self, device_code):
        """Invalidate an device code after use.

        :param client_id: Unicode client identifier.
        :param code: The device code grant (request.device_code).
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        raise NotImplementedError('Subclasses must implement this method.')

