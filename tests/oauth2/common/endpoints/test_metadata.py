# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from oauthlib.oauth2 import MetadataEndpoint
from oauthlib.oauth2 import TokenEndpoint

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
