"""
oauthlib.oauth2.rfc6749.tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains methods for adding device codes to requests.

- Bearer https://tools.ietf.org/html/rfc6750
"""
from __future__ import absolute_import, unicode_literals

import common

from oauth2.rfc6749.tokens import OAuth2Token, TokenBase

def random_device_code_generator(request):
    """
    :param request: OAuthlib request.
    :type request: oauthlib.common.Request
    """

    return common.generate_token()

def random_user_code_generator(request):
    """
    :param request: OAuthlib request.
    :type request: oauthlib.common.Request
    """

    first_component = common.generate_token(length=4)
    second_component = common.generate_token(length=4)

    return '{}-{}'.format(first_component, second_component)

class DeviceToken(TokenBase):
    __slots__ = (
        'request_validator', 'device_code_generator', 'user_code_generator',
        'expires_in'
    )

    def __init__(self, request_validator=None,
                 device_code_generator=None,
                 user_code_generator=None,
                 expires_in=None):
        self.request_validator = request_validator
        self.device_code_generator = device_code_generator or random_device_code_generator
        self.user_code_generator = user_code_generator or random_user_code_generator
        self.expires_in = expires_in or 3600

    def create_token(self, request, save_token=True):
        """
        Create a DeviceToken.
        
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param save_token:
        """

        if callable(self.expires_in):
            expires_in = self.expires_in(request)
        else:
            expires_in = self.expires_in

        request.expires_in = expires_in

        token = {
            'device_code': self.token_generator(request),
            'user_code': '',
            'verification_uri': '',
            'verification_uri_complete': '',
            'expires_in': expires_in,
            'interval': 'Bearer'
        }

        # If provided, include - this is optional in some cases https://tools.ietf.org/html/rfc6749#section-3.3 but
        # there is currently no mechanism to coordinate issuing a token for only a subset of the requested scopes so
        # all tokens issued are for the entire set of requested scopes.
        if request.scopes is not None:
            token['scope'] = ' '.join(request.scopes)

        token.update(request.extra_credentials or {})

        # Create our own custom token type
        #
        token = OAuth2Token(token)

        if save_token:
            self.request_validator.save_device_code(token, request)

        return token

    def validate_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        return self.request_validator.validate_device_token(request.scopes, request)

    def estimate_type(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        
        """
        This token type is not used as an authorization method but
        as a method of getting an access token so we return 0.
        """
        return 0