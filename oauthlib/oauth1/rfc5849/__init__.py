# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth1.rfc5849
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 1.0 RFC 5849 requests.
"""

import logging
log = logging.getLogger("oauthlib")

import sys
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

if sys.version_info[0] == 3:
    bytes_type = bytes
else:
    bytes_type = str

from oauthlib.common import Request, urlencode, generate_nonce
from oauthlib.common import generate_timestamp, to_unicode
from . import parameters, signature

SIGNATURE_HMAC = "HMAC-SHA1"
SIGNATURE_RSA = "RSA-SHA1"
SIGNATURE_PLAINTEXT = "PLAINTEXT"
SIGNATURE_METHODS = (SIGNATURE_HMAC, SIGNATURE_RSA, SIGNATURE_PLAINTEXT)

SIGNATURE_TYPE_AUTH_HEADER = 'AUTH_HEADER'
SIGNATURE_TYPE_QUERY = 'QUERY'
SIGNATURE_TYPE_BODY = 'BODY'

CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'


class Client(object):
    """A client used to sign OAuth 1.0 RFC 5849 requests"""
    def __init__(self, client_key,
            client_secret=None,
            resource_owner_key=None,
            resource_owner_secret=None,
            callback_uri=None,
            signature_method=SIGNATURE_HMAC,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            rsa_key=None, verifier=None, realm=None,
            encoding='utf-8', decoding=None,
            nonce=None, timestamp=None):
        """Create an OAuth 1 client.

        :param client_key: Client key (consumer key), mandatory.
        :param resource_owner_key: Resource owner key (oauth token).
        :param resource_owner_secret: Resource owner secret (oauth token secret).
        :param callback_uri: Callback used when obtaining request token.
        :param signature_method: SIGNATURE_HMAC, SIGNATURE_RSA or SIGNATURE_PLAINTEXT.
        :param signature_type: SIGNATURE_TYPE_AUTH_HEADER (default),
                               SIGNATURE_TYPE_QUERY or SIGNATURE_TYPE_BODY
                               depending on where you want to embed the oauth
                               credentials.
        :param rsa_key: RSA key used with SIGNATURE_RSA.
        :param verifier: Verifier used when obtaining an access token.
        :param realm: Realm (scope) to which access is being requested.
        :param encoding: If you provide non-unicode input you may use this
                         to have oauthlib automatically convert.
        :param decoding: If you wish that the returned uri, headers and body
                         from sign be encoded back from unicode, then set
                         decoding to your preferred encoding, i.e. utf-8.
        :param nonce: Use this nonce instead of generating one. (Mainly for testing)
        :param timestamp: Use this timestamp instead of using current. (Mainly for testing)
        """
        # Convert to unicode using encoding if given, else assume unicode
        encode = lambda x: to_unicode(x, encoding) if encoding else x

        self.client_key = encode(client_key)
        self.client_secret = encode(client_secret)
        self.resource_owner_key = encode(resource_owner_key)
        self.resource_owner_secret = encode(resource_owner_secret)
        self.signature_method = encode(signature_method)
        self.signature_type = encode(signature_type)
        self.callback_uri = encode(callback_uri)
        self.rsa_key = encode(rsa_key)
        self.verifier = encode(verifier)
        self.realm = encode(realm)
        self.encoding = encode(encoding)
        self.decoding = encode(decoding)
        self.nonce = encode(nonce)
        self.timestamp = encode(timestamp)

        if self.signature_method == SIGNATURE_RSA and self.rsa_key is None:
            raise ValueError('rsa_key is required when using RSA signature method.')

    def get_oauth_signature(self, request):
        """Get an OAuth signature to be used in signing a request

        To satisfy `section 3.4.1.2`_ item 2, if the request argument's
        headers dict attribute contains a Host item, its value will
        replace any netloc part of the request argument's uri attribute
        value.

        .. _`section 3.4.1.2`: http://tools.ietf.org/html/rfc5849#section-3.4.1.2
        """
        if self.signature_method == SIGNATURE_PLAINTEXT:
            # fast-path
            return signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

        uri, headers, body = self._render(request)

        collected_params = signature.collect_parameters(
            uri_query=urlparse.urlparse(uri).query,
            body=body,
            headers=headers)
        log.debug("Collected params: {0}".format(collected_params))

        normalized_params = signature.normalize_parameters(collected_params)
        normalized_uri = signature.normalize_base_string_uri(uri,
            headers.get('Host', None))
        log.debug("Normalized params: {0}".format(normalized_params))
        log.debug("Normalized URI: {0}".format(normalized_uri))

        base_string = signature.construct_base_string(request.http_method,
            normalized_uri, normalized_params)

        log.debug("Base signing string: {0}".format(base_string))

        if self.signature_method == SIGNATURE_HMAC:
            sig = signature.sign_hmac_sha1(base_string, self.client_secret,
                self.resource_owner_secret)
        elif self.signature_method == SIGNATURE_RSA:
            sig = signature.sign_rsa_sha1(base_string, self.rsa_key)
        else:
            sig = signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

        log.debug("Signature: {0}".format(sig))
        return sig

    def get_oauth_params(self):
        """Get the basic OAuth parameters to be used in generating a signature.
        """
        nonce = (generate_nonce()
                 if self.nonce is None else self.nonce)
        timestamp = (generate_timestamp()
                     if self.timestamp is None else self.timestamp)
        params = [
            ('oauth_nonce', nonce),
            ('oauth_timestamp', timestamp),
            ('oauth_version', '1.0'),
            ('oauth_signature_method', self.signature_method),
            ('oauth_consumer_key', self.client_key),
        ]
        if self.resource_owner_key:
            params.append(('oauth_token', self.resource_owner_key))
        if self.callback_uri:
            params.append(('oauth_callback', self.callback_uri))
        if self.verifier:
            params.append(('oauth_verifier', self.verifier))

        return params

    def _render(self, request, formencode=False, realm=None):
        """Render a signed request according to signature type

        Returns a 3-tuple containing the request URI, headers, and body.

        If the formencode argument is True and the body contains parameters, it
        is escaped and returned as a valid formencoded string.
        """
        # TODO what if there are body params on a header-type auth?
        # TODO what if there are query params on a body-type auth?

        uri, headers, body = request.uri, request.headers, request.body

        # TODO: right now these prepare_* methods are very narrow in scope--they
        # only affect their little thing. In some cases (for example, with
        # header auth) it might be advantageous to allow these methods to touch
        # other parts of the request, like the headers—so the prepare_headers
        # method could also set the Content-Type header to x-www-form-urlencoded
        # like the spec requires. This would be a fundamental change though, and
        # I'm not sure how I feel about it.
        if self.signature_type == SIGNATURE_TYPE_AUTH_HEADER:
            headers = parameters.prepare_headers(request.oauth_params, request.headers, realm=realm)
        elif self.signature_type == SIGNATURE_TYPE_BODY and request.decoded_body is not None:
            body = parameters.prepare_form_encoded_body(request.oauth_params, request.decoded_body)
            if formencode:
                body = urlencode(body)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        elif self.signature_type == SIGNATURE_TYPE_QUERY:
            uri = parameters.prepare_request_uri_query(request.oauth_params, request.uri)
        else:
            raise ValueError('Unknown signature type specified.')

        return uri, headers, body

    def sign(self, uri, http_method='GET', body=None, headers=None, realm=None):
        """Sign a request

        Signs an HTTP request with the specified parts.

        Returns a 3-tuple of the signed request's URI, headers, and body.
        Note that http_method is not returned as it is unaffected by the OAuth
        signing process. Also worth noting is that duplicate parameters
        will be included in the signature, regardless of where they are
        specified (query, body).

        The body argument may be a dict, a list of 2-tuples, or a formencoded
        string. The Content-Type header must be 'application/x-www-form-urlencoded'
        if it is present.

        If the body argument is not one of the above, it will be returned
        verbatim as it is unaffected by the OAuth signing process. Attempting to
        sign a request with non-formencoded data using the OAuth body signature
        type is invalid and will raise an exception.

        If the body does contain parameters, it will be returned as a properly-
        formatted formencoded string.

        Body may not be included if the http_method is either GET or HEAD as
        this changes the semantic meaning of the request.

        All string data MUST be unicode or be encoded with the same encoding
        scheme supplied to the Client constructor, default utf-8. This includes
        strings inside body dicts, for example.
        """
        # normalize request data
        request = Request(uri, http_method, body, headers,
                          encoding=self.encoding)

        # sanity check
        content_type = request.headers.get('Content-Type', None)
        multipart = content_type and content_type.startswith('multipart/')
        should_have_params = content_type == CONTENT_TYPE_FORM_URLENCODED
        has_params = request.decoded_body is not None
        # 3.4.1.3.1.  Parameter Sources
        # [Parameters are collected from the HTTP request entity-body, but only
        # if [...]:
        #    *  The entity-body is single-part.
        if multipart and has_params:
            raise ValueError("Headers indicate a multipart body but body contains parameters.")
        #    *  The entity-body follows the encoding requirements of the
        #       "application/x-www-form-urlencoded" content-type as defined by
        #       [W3C.REC-html40-19980424].
        elif should_have_params and not has_params:
            raise ValueError("Headers indicate a formencoded body but body was not decodable.")
        #    *  The HTTP request entity-header includes the "Content-Type"
        #       header field set to "application/x-www-form-urlencoded".
        elif not should_have_params and has_params:
            raise ValueError("Body contains parameters but Content-Type header was not set.")

        # 3.5.2.  Form-Encoded Body
        # Protocol parameters can be transmitted in the HTTP request entity-
        # body, but only if the following REQUIRED conditions are met:
        # o  The entity-body is single-part.
        # o  The entity-body follows the encoding requirements of the
        #    "application/x-www-form-urlencoded" content-type as defined by
        #    [W3C.REC-html40-19980424].
        # o  The HTTP request entity-header includes the "Content-Type" header
        #    field set to "application/x-www-form-urlencoded".
        elif self.signature_type == SIGNATURE_TYPE_BODY and not (
                should_have_params and has_params and not multipart):
            raise ValueError('Body signatures may only be used with form-urlencoded content')

        # We amend http://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
        # with the clause that parameters from body should only be included
        # in non GET or HEAD requests. Extracting the request body parameters
        # and including them in the signature base string would give semantic
        # meaning to the body, which it should not have according to the
        # HTTP 1.1 spec.
        elif http_method.upper() in ('GET', 'HEAD') and has_params:
            raise ValueError('GET/HEAD requests should not include body.')

        # generate the basic OAuth parameters
        request.oauth_params = self.get_oauth_params()

        # generate the signature
        request.oauth_params.append(('oauth_signature', self.get_oauth_signature(request)))

        # render the signed request and return it
        uri, headers, body = self._render(request, formencode=True,
                realm=(realm or self.realm))

        if self.decoding:
            log.debug('Encoding URI, headers and body to %s.', self.decoding)
            uri = uri.encode(self.decoding)
            body = body.encode(self.decoding) if body else body
            new_headers = {}
            for k, v in headers.items():
                new_headers[k.encode(self.decoding)] = v.encode(self.decoding)
            headers = new_headers
        return uri, headers, body
