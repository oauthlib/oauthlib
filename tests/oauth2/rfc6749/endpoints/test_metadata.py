# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from oauthlib.oauth2 import MetadataEndpoint
from oauthlib.oauth2 import TokenEndpoint
from oauthlib.oauth2 import Server

from ....unittest import TestCase


class MetadataEndpointTest(TestCase):
    def setUp(self):
        self.metadata = {
            "issuer": 'https://foo.bar'
        }

    def test_token_endpoint(self):
        endpoint = TokenEndpoint(None, None, grant_types={"password": None})
        metadata = MetadataEndpoint([endpoint], {
            "issuer": 'https://foo.bar',
            "token_endpoint": "https://foo.bar/token"
        })
        self.assertIn("grant_types_supported", metadata.claims)
        self.assertEqual(metadata.claims["grant_types_supported"], ["password"])

    def test_token_endpoint_overridden(self):
        endpoint = TokenEndpoint(None, None, grant_types={"password": None})
        metadata = MetadataEndpoint([endpoint], {
            "issuer": 'https://foo.bar',
            "token_endpoint": "https://foo.bar/token",
            "grant_types_supported": ["pass_word_special_provider"]
        })
        self.assertIn("grant_types_supported", metadata.claims)
        self.assertEqual(metadata.claims["grant_types_supported"], ["pass_word_special_provider"])

    def test_mandatory_fields(self):
        metadata = MetadataEndpoint([], self.metadata)
        self.assertIn("issuer", metadata.claims)
        self.assertEqual(metadata.claims["issuer"], 'https://foo.bar')

    def test_server_metadata(self):
        endpoint = Server(None)
        metadata = MetadataEndpoint([endpoint], {
            "issuer": 'https://foo.bar',
            "authorization_endpoint": "https://foo.bar/authorize",
            "introspection_endpoint": "https://foo.bar/introspect",
            "revocation_endpoint": "https://foo.bar/revoke",
            "token_endpoint": "https://foo.bar/token",
            "jwks_uri": "https://foo.bar/certs",
            "scopes_supported": ["email", "profile"]
        })
        expected_claims = {
            "issuer": "https://foo.bar",
            "authorization_endpoint": "https://foo.bar/authorize",
            "introspection_endpoint": "https://foo.bar/introspect",
            "revocation_endpoint": "https://foo.bar/revoke",
            "token_endpoint": "https://foo.bar/token",
            "jwks_uri": "https://foo.bar/certs",
            "scopes_supported": ["email", "profile"],
            "grant_types_supported": [
                "authorization_code",
                "password",
                "client_credentials",
                "refresh_token",
                "implicit"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic"
            ],
            "response_types_supported": [
                "code",
                "token"
            ],
            "response_modes_supported": [
                "query",
                "fragment"
            ],
            "code_challenge_methods_supported": [
                "plain",
                "S256"
            ],
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic"
            ],
            "introspection_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic"
            ]
        }

        def sort_list(claims):
            for k in claims.keys():
                claims[k] = sorted(claims[k])

        sort_list(metadata.claims)
        sort_list(expected_claims)
        self.assertEqual(sorted(metadata.claims.items()), sorted(expected_claims.items()))
