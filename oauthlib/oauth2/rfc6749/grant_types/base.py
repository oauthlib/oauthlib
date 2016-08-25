# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc6749.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import unicode_literals, absolute_import

import logging

from oauthlib.common import add_params_to_uri
from oauthlib.oauth2.rfc6749 import errors, utils

log = logging.getLogger(__name__)


class GrantTypeBase(object):
    error_uri = None
    request_validator = None
    default_response_mode = 'fragment'

    def create_authorization_response(self, request, token_handler):
        raise NotImplementedError('Subclasses must implement this method.')

    def create_token_response(self, request, token_handler):
        raise NotImplementedError('Subclasses must implement this method.')

    def add_token(self, token, token_handler, request):
        # Only add a hybrid access token on auth step if asked for
        if not request.response_type in ["token", "code token", "id_token token", "code id_token token"]:
            return token

        token.update(token_handler.create_token(request, refresh_token=False))
        return token

    def validate_grant_type(self, request):
        client_id = getattr(request, 'client_id', None)
        if not self.request_validator.validate_grant_type(client_id,
                                                          request.grant_type, request.client, request):
            log.debug('Unauthorized from %r (%r) access to grant type %s.',
                      request.client_id, request.client, request.grant_type)
            raise errors.UnauthorizedClientError(request=request)

    def validate_scopes(self, request):
        if not request.scopes:
            request.scopes = utils.scope_to_list(request.scope) or utils.scope_to_list(
                self.request_validator.get_default_scopes(request.client_id, request))
        log.debug('Validating access to scopes %r for client %r (%r).',
                  request.scopes, request.client_id, request.client)
        if not self.request_validator.validate_scopes(request.client_id,
                                                      request.scopes, request.client, request):
            raise errors.InvalidScopeError(request=request)

    def prepare_authorization_response(self, request, token, headers, body, status):
        """Place token according to response mode.

        Base classes can define a default response mode for their authorization
        response by overriding the static `default_response_mode` member.
        """
        request.response_mode = request.response_mode or self.default_response_mode

        if request.response_mode not in ('query', 'fragment'):
            log.debug('Overriding invalid response mode %s with %s',
                      request.response_mode, self.default_response_mode)
            request.response_mode = self.default_response_mode

        token_items = token.items()

        if request.response_type == 'none':
            state = token.get('state', None)
            if state:
                token_items = [('state', state)]
            else:
                token_items = []

        if request.response_mode == 'query':
            headers['Location'] = add_params_to_uri(
                request.redirect_uri, token_items, fragment=False)
            return headers, body, status

        if request.response_mode == 'fragment':
            headers['Location'] = add_params_to_uri(
                request.redirect_uri, token_items, fragment=True)
            return headers, body, status

        raise NotImplementedError(
            'Subclasses must set a valid default_response_mode')
