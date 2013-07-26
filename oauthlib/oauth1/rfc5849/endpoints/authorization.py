# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth1.rfc5849.endpoints.authorization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 1.0 RFC 5849 requests.
"""

from oauthlib.common import Request, add_params_to_uri

from .base import BaseEndpoint
from .. import errors


class AuthorizationEndpoint(BaseEndpoint):
    """An endpoint responsible for letting authenticated users authorize access
    to their protected resources to a client.

    Typical use would be to have two views, one for displaying the authorization
    form and one to process said form on submission.

    The first view will want to utilize ``get_realms_and_credentials`` to fetch
    requested realms and useful client credentials, such as name and
    description, to be used when creating the authorization form.

    During form processing you can use ``create_authorization_response`` to
    validate the request, create a verifier as well as prepare the final
    redirection URI used to send the user back to the client.

    See :doc:`validator` for details on which validator methods to implement
    for this endpoint.
    """

    def create_verifier(self, request, credentials):
        """Create and save a new request token.

        :param request: An oauthlib.common.Request object.
        :param credentials: A dict of extra token credentials.
        :returns: The verifier as a dict.
        """
        verifier = {
            'oauth_token': request.resource_owner_key,
            'oauth_verifier': self.token_generator(),
        }
        verifier.update(credentials)
        self.request_validator.save_verifier(
                request.resource_owner_key, verifier, request)
        return verifier

    def create_authorization_response(self, uri, http_method='GET', body=None,
            headers=None, realms=None, credentials=None):
        """Create an authorization response, with a new request token if valid.

        :param uri: The full URI of the token request.
        :param http_method: A valid HTTP verb, i.e. GET, POST, PUT, HEAD, etc.
        :param body: The request body as a string.
        :param headers: The request headers as a dict.
        :param credentials: A list of credentials to include in the verifier.
        :returns: A tuple of 4 elements.
                  1. The URI to be used to redirect the user back to client.
                  2. A dict of headers to set on the response.
                  3. The response body as a string.
                  4. The response status code as an integer.

        An example of a valid request::

            >>> from your_validator import your_validator
            >>> from oauthlib.oauth1 import RequestTokenEndpoint
            >>> endpoint = RequestTokenEndpoint(your_validator)
            >>> u, h, b, s = endpoint.create_request_token_response(
            ...     'https://your.provider/request_token?foo=bar',
            ...     headers={
            ...         'Authorization': 'OAuth realm=movies user, oauth_....'
            ...     },
            ...     credentials={
            ...         'extra': 'argument',
            ...     })
            >>> u
            'https://the.client/callback?oauth_verifier=...&mextra=argument'
            >>> h
            {}
            >>> b
            ''
            >>> s
            302
        """
        request = self._create_request(uri, http_method=http_method, body=body,
                headers=headers)

        if not request.resource_owner_key:
            raise errors.InvalidRequestError(
                    'Missing mandatory parameter oauth_token.')
        if not self.request_validator.verify_request_token(
                request.resource_owner_key, request):
            raise errors.InvalidClientError()

        request.realms = realms
        if (request.realms and not self.request_validator.verify_realms(
                request.resource_owner_key, request.realms, request)):
            raise errors.InvalidRequestError(
                    description=('User granted access to realms outside of '
                                 'what the client may request.'))

        redirect_uri = self.request_validator.get_redirect_uri(
                request.resource_owner_key, request)
        verifier = self.create_verifier(request, credentials or {})
        uri = add_params_to_uri(redirect_uri, verifier.items())
        return uri, {}, None, 302

    def get_realms_and_credentials(self, uri, http_method='GET', body=None,
            headers=None):
        """Fetch realms and credentials for the presented request token.

        :param uri: The full URI of the token request.
        :param http_method: A valid HTTP verb, i.e. GET, POST, PUT, HEAD, etc.
        :param body: The request body as a string.
        :param headers: The request headers as a dict.
        :returns: A tuple of 2 elements.
                  1. A list of request realms.
                  2. A dict of credentials which may be useful in creating the
                  authorization form.
        """
        request = self._create_request(uri, http_method=http_method, body=body,
                headers=headers)

        if not self.request_validator.verify_request_token(
                request.resource_owner_key, request):
            raise errors.InvalidClientError()

        realms = self.request_validator.get_realms(
                request.resource_owner_key, request)
        return realms, {'resource_owner_key': request.resource_owner_key}
