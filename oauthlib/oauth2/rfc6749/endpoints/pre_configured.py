# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""
from ..tokens import BearerToken
from ..grant_types import AuthorizationCodeGrant
from ..grant_types import ImplicitGrant
from ..grant_types import ResourceOwnerPasswordCredentialsGrant
from ..grant_types import ClientCredentialsGrant
from ..grant_types import RefreshTokenGrant

from .authorization import AuthorizationEndpoint
from .token import TokenEndpoint
from .resource import ResourceEndpoint


class Server(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring all four major grant types."""

    def __init__(self, request_validator, token_expires_in=None,
            token_generator=None, *args, **kwargs):
        auth_grant = AuthorizationCodeGrant(request_validator)
        implicit_grant = ImplicitGrant(request_validator)
        password_grant = ResourceOwnerPasswordCredentialsGrant(request_validator)
        credentials_grant = ClientCredentialsGrant(request_validator)
        refresh_grant = RefreshTokenGrant(request_validator)
        bearer = BearerToken(request_validator, token_generator,
                expires_in=token_expires_in)
        AuthorizationEndpoint.__init__(self, default_response_type='code',
                response_types={
                    'code': auth_grant,
                    'token': implicit_grant,
                },
                default_token_type=bearer)
        TokenEndpoint.__init__(self, default_grant_type='authorization_code',
                grant_types={
                    'authorization_code': auth_grant,
                    'password': password_grant,
                    'client_credentials': credentials_grant,
                    'refresh_token': refresh_grant,
                },
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})


class WebApplicationServer(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring Authorization code grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None,
            token_expires_in=None, **kwargs):
        """Construct a new web application server.

        :param request_validator: An implementation of oauthlib.oauth2.RequestValidator.
        :param token_generator: A function to generate a token from a request.
        :param kwargs: Extra parameters to pass to authorization endpoint,
                       token endpoint and resource endpoint constructors.
        """
        auth_grant = AuthorizationCodeGrant(request_validator)
        refresh_grant = RefreshTokenGrant(request_validator)
        bearer = BearerToken(request_validator, token_generator,
                expires_in=token_expires_in)
        AuthorizationEndpoint.__init__(self, default_response_type='code',
                response_types={'code': auth_grant},
                default_token_type=bearer)
        TokenEndpoint.__init__(self, default_grant_type='authorization_code',
                grant_types={
                    'authorization_code': auth_grant,
                    'refresh_token': refresh_grant,
                },
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})


class MobileApplicationServer(AuthorizationEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring Implicit code grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None,
            token_expires_in=None, **kwargs):
        implicit_grant = ImplicitGrant(request_validator)
        bearer = BearerToken(request_validator, token_generator,
                expires_in=token_expires_in)
        AuthorizationEndpoint.__init__(self, default_response_type='token',
                response_types={'token': implicit_grant},
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})


class LegacyApplicationServer(TokenEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring Resource Owner Password Credentials grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None,
            token_expires_in=None, **kwargs):
        password_grant = ResourceOwnerPasswordCredentialsGrant(request_validator)
        refresh_grant = RefreshTokenGrant(request_validator)
        bearer = BearerToken(request_validator, token_generator,
                expires_in=token_expires_in)
        TokenEndpoint.__init__(self, default_grant_type='password',
                grant_types={
                    'password': password_grant,
                    'refresh_token': refresh_grant,
                },
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})


class BackendApplicationServer(TokenEndpoint, ResourceEndpoint):
    """An all-in-one endpoint featuring Client Credentials grant and Bearer tokens."""

    def __init__(self, request_validator, token_generator=None,
            token_expires_in=None, **kwargs):
        credentials_grant = ClientCredentialsGrant(request_validator)
        bearer = BearerToken(request_validator, token_generator,
                expires_in=token_expires_in)
        TokenEndpoint.__init__(self, default_grant_type='client_credentials',
                grant_types={'client_credentials': credentials_grant},
                default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                token_types={'Bearer': bearer})
