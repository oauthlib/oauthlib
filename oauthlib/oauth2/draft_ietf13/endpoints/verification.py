# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.common
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 Draft IETF 13.
"""
from __future__ import absolute_import, unicode_literals

import logging

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import utils

from .base import BaseEndpoint, catch_errors_and_unavailability

log = logging.getLogger(__name__)


class VerificationEndpoint(BaseEndpoint):

    """Verification endpoint - used by the client to obtain authorization
    from the resource owner via the device code

    Since requests to the authorization endpoint result in user
    authentication and the transmission of clear-text credentials (in the
    HTTP response), the authorization server MUST require the use of TLS
    as described in Section 3.1 when sending requests to the
    authorization endpoint::

        # We will deny any request which URI schema is not with https

    The authorization server MUST support the use of the HTTP "POST"
    method [RFC2616] for the code endpoint.

    Parameters sent without a value MUST be treated as if they were
    omitted from the request.  The authorization server MUST ignore
    unrecognized request parameters.  Request and response parameters
    MUST NOT be included more than once:

        # Enforced through the design of oauthlib.common.Request

    .. _`Section 3.1`: https://tools.ietf.org/html/draft-ietf-oauth-device-flow-13#section-3.1
    """

    def __init__(self, default_grant_type, default_token_type):
        BaseEndpoint.__init__(self)

        self._default_grant_type = default_grant_type
        self._default_token_type = default_token_type

    @property
    def default_token_type(self):
        return self._default_token_type

    @catch_errors_and_unavailability
    def create_verification_response(self, uri, http_method='POST', body=None,
                                      headers=None, scopes=None, credentials=None):
        """Extract response_type and route to the designated handler."""
        request = Request(
            uri, http_method=http_method, body=body, headers=headers)
        request.scopes = scopes
        # TODO: decide whether this should be a required argument
        request.user = None     # TODO: explain this in docs
        for k, v in (credentials or {}).items():
            setattr(request, k, v)
   
        return self._default_grant_type.create_verification_response(
            request, self.default_token_type)

    @catch_errors_and_unavailability
    def validate_verification_request(self, uri, http_method='POST', body=None,
                                       headers=None):
        """Extract response_type and route to the designated handler."""
        request = Request(
            uri, http_method=http_method, body=body, headers=headers)

        request.scopes = utils.scope_to_list(request.scope)

        return self._default_grant_type.validate_verification_request(request)
