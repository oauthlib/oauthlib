# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import urllib

from ...unittest import TestCase

from oauthlib.oauth2.draft25 import AuthorizationServer
from oauthlib.oauth2.draft25.exceptions import (InvalidClientIdentifier,
    MissingRedirectURI, InvalidRedirectURI)

class AuthorizationEndpointTestCase(TestCase):
    """
    Tests for Sections 3.1 and 4.1
    """
    def test_redirection_uri_invalid_client_identifier(self):
        class Server(AuthorizationServer):
            def client_redirect_uris(self, client_identifier):
                raise InvalidClientIdentifier(client_identifier)
        server = Server()

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1.2.1
        # If the request fails due to a missing, invalid, or mismatching
        # redirection URI, or if the client identifier is missing or invalid,
        # the authorization server SHOULD inform the resource owner of the
        # error, and MUST NOT automatically redirect the user-agent to the
        # invalid redirection URI.
        self.assertRaises(InvalidClientIdentifier, server.redirect_uri,
                          'invalid_client_identifier')

    def test_redirect_uri_is_valid_0_registered_uris(self):
        class Server(AuthorizationServer):
            def client_redirect_uris(self, client_identifier):
                return []
        server = Server()

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.3
        # If multiple redirection URIs have been registered, if only part of
        # the redirection URI has been registered, or if no redirection URI has
        # been registered, the client MUST include a redirection URI.
        self.assertRaises(MissingRedirectURI, server.redirect_uri,
                          'client_identifier')

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2
        # The redirection endpoint URI MUST be an absolute URI
        self.assertRaises(InvalidRedirectURI, server.redirect_uri,
                          'client_identifier', '/path/to/redirect')

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2
        # The endpoint URI MAY include an "application/x-www-form-urlencoded"
        # formatted query component
        request_redirect_uri = 'http://example.com/?foo=bar'
        redirect_uri = server.redirect_uri('client_identifier',
                                           request_redirect_uri)
        self.assertEqual(request_redirect_uri, redirect_uri)

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2
        # The endpoint URI MUST NOT include a fragment component.
        self.assertRaises(InvalidRedirectURI, server.redirect_uri,
                          'client_identifier', 'http://example.com/#hash')

    def test_redirect_uri_is_valid_1_registered_uri(self):
        class Server(AuthorizationServer):
            uri = 'http://example.com/path/to/redirect/'
            def client_redirect_uris(self, client_identifier):
                return (self.uri,)
        server = Server()

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.3
        # If multiple redirection URIs have been registered, if only part of
        # the redirection URI has been registered, or if no redirection URI has
        # been registered, the client MUST include a redirection URI.
        redirect_uri = server.redirect_uri('client_identifier')
        self.assertEqual(redirect_uri, server.uri)

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.2
        # The authorization server SHOULD require the registration of the URI
        # scheme, authority, and path (allowing the client to dynamically vary
        # only the query component of the redirection URI when requesting
        # authorization).
        request_redirect_uri = '{0}?{1}'.format(
            server.uri,
            urllib.urlencode({'foo': 'bar'}),
        )
        redirect_uri = server.redirect_uri('client_identifier',
                                           request_redirect_uri)
        self.assertEqual(request_redirect_uri, redirect_uri)

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.3
        # When a redirection URI is included in an authorization request, the
        # authorization server MUST compare and match the value received
        # against at least one of the registered redirection URIs
        self.assertRaises(InvalidRedirectURI, server.redirect_uri,
                          'client_identifier',
                          'http://example.com/invalid/path/')

    def test_redirect_uri_is_valid_2_registered_uris(self):
        class Server(AuthorizationServer):
            uris = (
                'http://example.com/path/to/redirect/',
                'http://example.com/another/path/to/redirect/',
            )
            def client_redirect_uris(self, client_identifier):
                return self.uris
        server = Server()

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.3
        # If multiple redirection URIs have been registered, if only part of
        # the redirection URI has been registered, or if no redirection URI has
        # been registered, the client MUST include a redirection URI.
        self.assertRaises(MissingRedirectURI, server.redirect_uri,
                          'client_identifier')

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.3
        # When a redirection URI is included in an authorization request, the
        # authorization server MUST compare and match the value received
        # against at least one of the registered redirection URIs
        self.assertRaises(InvalidRedirectURI, server.redirect_uri,
                          'client_identifier',
                          'http://example.com/invalid/path/')

        # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.2
        # The authorization server MAY allow the client to register multiple
        # redirection endpoints.
        for uri in server.uris:
            self.assertEqual(server.redirect_uri('client_identifier', uri),
                             uri)

