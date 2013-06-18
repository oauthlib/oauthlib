# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth1.rfc5849
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 1.0 RFC 5849 requests.
"""

from oauthlib.common import Request, add_params_to_uri

from .base import BaseEndpoint
from .. import errors


class AuthorizationEndpoint(BaseEndpoint):

    def create_verifier(self, request, credentials):
        verifier = {
            'oauth_token': request.oauth_token,
            'oauth_verifier': self.token_generator(),
        }
        verifier.update(credentials)
        self.request_validator.save_verifier(
                request.oauth_token, verifier, request)
        return verifier

    def create_authorization_response(self, uri, http_method='GET', body=None,
            headers=None, realms=None, credentials=None):
        request = Request(uri, http_method=http_method, body=body,
                headers=headers)

        if not self.request_validator.verify_request_token(
                request.oauth_token, request):
            raise errors.InvalidClientError()
        if not request.oauth_token:
            raise NotImplementedError('request.oauth_token must be set after '
                                      'request token verification.')

        request.realms = realms
        if (request.realms and not self.request_validator.verify_realms(
                request.oauth_token, request.realms, request)):
            raise errors.InvalidRequestError(
                    description=('User granted access to realms outside of '
                                 'what the client may request.'))

        redirect_uri = self.request_validator.get_redirect_uri(
                request.oauth_token, request)
        verifier = self.create_verifier(request, credentials or {})
        uri = add_params_to_uri(redirect_uri, verifier.items())
        return uri, {}, None, 301

    def get_realms_and_credentials(self, uri, http_method='GET', body=None,
            headers=None):
        request = Request(uri, http_method=http_method, body=body,
                headers=headers)

        if not self.request_validator.verify_request_token(
                request.oauth_token, request):
            raise errors.InvalidClientError()

        realms = self.request_validator.get_realms(
                request.oauth_token, request)
        return realms, {'resource_owner_key': request.oauth_token}
