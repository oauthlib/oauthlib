# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.oauth2.draft_25
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 2.0 draft 25 requests.
"""

from oauthlib.common import Request, urlencode
from . import tokens

SIGNATURE_TYPE_AUTH_HEADER = u'AUTH_HEADER'
SIGNATURE_TYPE_QUERY = u'QUERY'
SIGNATURE_TYPE_BODY = u'BODY'
SIGNATURE_TYPE_MAC = u'MAC'


class Client(object):
    """A client used to sign OAuth 2.0 token-bearing requests"""
    def __init__(self, access_token,
            key=None,
            nonce=None,
            ext=u'',
            hash_algorithm=u'hmac-sha-1',
            signature_type=SIGNATURE_TYPE_AUTH_HEADER):

        self.access_token = access_token
        self.key = key
        self.nonce = nonce
        self.ext = ext
        self.hash_algorithm = hash_algorithm
        self.signature_type = signature_type

        if self.signature_type == SIGNATURE_TYPE_MAC and self.key is None:
            raise ValueError('key is required when using MAC signature type.')

    def _render(self, request, formencode=False):
        """Render a signed request according to signature type

        Returns a 3-tuple containing the request URI, headers, and body.

        If the formencode argument is True and the body contains parameters, it
        is escaped and returned as a valid formencoded string.
        """

        uri, headers, body = request.uri, request.headers, request.body

        # TODO: right now these prepare_* methods are very narrow in scope--they
        # only affect their little thing. In some cases (for example, with
        # header auth) it might be advantageous to allow these methods to touch
        # other parts of the request, like the headers—so the prepare_headers
        # method could also set the Content-Type header to x-www-form-urlencoded
        # like the spec requires. This would be a fundamental change though, and
        # I'm not sure how I feel about it.
        if self.signature_type == SIGNATURE_TYPE_AUTH_HEADER:
            headers = tokens.prepare_bearer_headers(self.access_token, request.headers)
        elif self.signature_type == SIGNATURE_TYPE_BODY and request.decoded_body is not None:
            body = tokens.prepare_bearer_body(self.access_token, request.decoded_body)
            if formencode:
                body = urlencode(body)
            headers['Content-Type'] = u'application/x-www-form-urlencoded'
        elif self.signature_type == SIGNATURE_TYPE_QUERY:
            uri = tokens.prepare_bearer_uri(self.access_token, request.uri)
        elif self.signature_type == SIGNATURE_TYPE_MAC:
            headers = tokens.prepare_mac_headers(self.access_token, uri,
                self.mac_key, request.http_method, nonce=self.nonce, body=body,
                headers=headers, ext=self.ext, hash_algorithm=self.hash_algorithm)
        else:
            raise ValueError('Unknown signature type specified.')

        return uri, headers, body

    def sign(self, uri, http_method=u'GET', body=None, headers=None):
        """Sign a request

        Signs an HTTP request with the specified parts.

        Returns a 3-tuple of the signed request's URI, headers, and body.
        Note that http_method is not returned as it is unaffected by the OAuth
        signing process.

        The body argument may be a dict, a list of 2-tuples, or a formencoded
        string. The Content-Type header must be 'application/x-www-form-urlencoded'
        if it is present.

        If the body argument is not one of the above, it will be returned
        verbatim as it is unaffected by the OAuth signing process. Attempting to
        sign a request with non-formencoded data using the OAuth body signature
        type is invalid and will raise an exception.

        If the body does contain parameters, it will be returned as a properly-
        formatted formencoded string.

        All string data MUST be unicode. This includes strings inside body
        dicts, for example.
        """
        # normalize request data
        request = Request(uri, http_method, body, headers)

        return self._render(request, formencode=True)

class Server(object):
    pass

