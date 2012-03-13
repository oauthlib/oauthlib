# -*- coding: utf-8 -*-
from __future__ import absolute_import

"""
oauthlib.oauth
~~~~~~~~~~~~~~

This module is a generic implementation of various logic needed
for signing OAuth requests.
"""

import urlparse

from . import parameters, signature, utils

SIGNATURE_HMAC = "HMAC-SHA1"
SIGNATURE_RSA = "RSA-SHA1"
SIGNATURE_PLAINTEXT = "PLAINTEXT"

SIGNATURE_TYPE_AUTH_HEADER = 'AUTH_HEADER'
SIGNATURE_TYPE_QUERY = 'QUERY'

class OAuthClient(object):
    """An OAuth client used to sign OAuth requests"""
    def __init__(self, client_key, client_secret,
            resource_owner_key, resource_owner_secret,
            signature_method=SIGNATURE_HMAC,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            callback_uri=None, rsa_key=None, verifier=None):
        self.client_key = client_key
        self.client_secret = client_secret
        self.resource_owner_key = resource_owner_key
        self.resource_owner_secret = resource_owner_secret
        self.signature_method = signature_method
        self.signature_type = signature_type
        self.callback_uri = callback_uri
        self.rsa_key = rsa_key
        self.verifier = verifier

    def get_oauth_signature(self, uri, http_method=u'GET', body=None,
            authorization_header=None):
        """Get an OAuth signature to be used in signing a request"""
        if self.signature_method == SIGNATURE_PLAINTEXT:
            # fast-path
            return signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

        query = urlparse.urlparse(uri).query
        params = signature.collect_parameters(uri_query=query,
            authorization_header=authorization_header, body=body)
        normalized_params = signature.normalize_parameters(params)
        normalized_uri = signature.normalize_base_string_uri(uri)
        base_string = signature.construct_base_string(http_method,
            normalized_uri, normalized_params)
        if self.signature_method == SIGNATURE_HMAC:
            return signature.sign_hmac_sha1(base_string, self.client_secret,
                self.resource_owner_secret)
        elif self.signature_method == SIGNATURE_RSA:
            return signature.sign_rsa_sha1(base_string, self.rsa_key)
        else:
            return signature.sign_plaintext(self.client_secret,
                self.resource_owner_secret)

    def get_oauth_params(self):
        """Get the basic OAuth parameters to be used in generating a signature.
        """
        params = [
            (u'oauth_nonce', utils.generate_nonce()),
            (u'oauth_timestamp', utils.generate_timestamp()),
            (u'oauth_version', '1.0'),
            (u'oauth_signature_method', self.signature_method),
            (u'oauth_consumer_key', self.client_key),
            (u'oauth_token', self.resource_owner_key),
        ]
        if self.callback_uri:
            params.append((u'oauth_callback', self.callback_uri))
        if self.verifier:
            params.append((u'oauth_verifier', self.verifier))

        return params

    def _contribute_parameters(self, uri, params):
        if self.signature_type == SIGNATURE_TYPE_AUTH_HEADER:
            authorization_header = parameters.prepare_authorization_header(
                params)
            complete_uri = uri
        else:
            authorization_header = None
            complete_uri = paramaters.prepare_request_uri_query(params, uri)

        return complete_uri, authorization_header

    def sign_request(self, uri, http_method=u'GET', body=None):
        """Get the signed uri and authorization header.
        Authorization header will be None if signature type is "query".
        """
        # get the OAuth params and contribute them to either the uri or
        # authorization header
        params = self.get_oauth_params()
        complete_uri, authorization_header = self._contribute_parameters(uri,
            params)

        # use the new uri and authorization header to generate a signature and
        # contribute that signature to the OAuth parameters
        oauth_signature = self.get_oauth_signature(complete_uri,
            http_method=http_method, body=body,
            authorization_header=authorization_header)
        params.append((u'oauth_signature', oauth_signature))

        # take the new OAuth params with signature and contribute the
        # now-complete parameters to the uri or authorization header
        return self._contribute_parameters(uri, params)

