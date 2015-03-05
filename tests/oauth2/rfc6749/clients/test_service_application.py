# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import os
from time import time

import jwt
from Crypto.PublicKey import RSA
from mock import patch

from oauthlib.common import Request
from oauthlib.oauth2 import ServiceApplicationClient

from ....unittest import TestCase


class ServiceApplicationClientTest(TestCase):

    gt = ServiceApplicationClient.grant_type

    private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDk1/bxy"
        "S8Q8jiheHeYYp/4rEKJopeQRRKKpZI4s5i+UPwVpupG\nAlwXWfzXw"
        "SMaKPAoKJNdu7tqKRniqst5uoHXw98gj0x7zamu0Ck1LtQ4c7pFMVa"
        "h\n5IYGhBi2E9ycNS329W27nJPWNCbESTu7snVlG8V8mfvGGg3xNjT"
        "MO7IdrwIDAQAB\nAoGBAOQ2KuH8S5+OrsL4K+wfjoCi6MfxCUyqVU9"
        "GxocdM1m30WyWRFMEz2nKJ8fR\np3vTD4w8yplTOhcoXdQZl0kRoaD"
        "zrcYkm2VvJtQRrX7dKFT8dR8D/Tr7dNQLOXfC\nDY6xveQczE7qt7V"
        "k7lp4FqmxBsaaEuokt78pOOjywZoInjZhAkEA9wz3zoZNT0/i\nrf6"
        "qv2qTIeieUB035N3dyw6f1BGSWYaXSuerDCD/J1qZbAPKKhyHZbVaw"
        "Ft3UMhe\n542UftBaxQJBAO0iJy1I8GQjGnS7B3yvyH3CcLYGy296+"
        "XO/2xKp/d/ty1OIeovx\nC60pLNwuFNF3z9d2GVQAdoQ89hUkOtjZL"
        "eMCQQD0JO6oPHUeUjYT+T7ImAv7UKVT\nSuy30sKjLzqoGw1kR+wv7"
        "C5PeDRvscs4wa4CW9s6mjSrMDkDrmCLuJDtmf55AkEA\nkmaMg2PNr"
        "jUR51F0zOEFycaaqXbGcFwe1/xx9zLmHzMDXd4bsnwt9kk+fe0hQzV"
        "S\nJzatanQit3+feev1PN3QewJAWv4RZeavEUhKv+kLe95Yd0su7lT"
        "LVduVgh4v5yLT\nGa6FHdjGPcfajt+nrpB1n8UQBEH9ZxniokR/IPv"
        "dMlxqXA==\n-----END RSA PRIVATE KEY-----"
    )

    subject = 'resource-owner@provider.com'

    issuer = 'the-client@provider.com'

    audience = 'https://provider.com/token'

    client_id = "someclientid"
    scope = ["/profile"]
    kwargs = {
        "some": "providers",
        "require": "extra arguments"
    }

    body = "isnot=empty"

    body_up = "not=empty&grant_type=%s" % gt
    body_kwargs = body_up + "&some=providers&require=extra+arguments"

    token_json = ('{   "access_token":"2YotnFZFEjr1zCsicMWpAA",'
                  '    "token_type":"example",'
                  '    "expires_in":3600,'
                  '    "scope":"/profile",'
                  '    "example_parameter":"example_value"}')
    token = {
        "access_token": "2YotnFZFEjr1zCsicMWpAA",
        "token_type": "example",
        "expires_in": 3600,
        "scope": ["/profile"],
        "example_parameter": "example_value"
    }

    @patch('time.time')
    def test_request_body(self, t):
        t.return_value = time()
        self.token['expires_at'] = self.token['expires_in'] + t.return_value

        client = ServiceApplicationClient(
                self.client_id, private_key=self.private_key)

        # Basic with min required params
        body = client.prepare_request_body(issuer=self.issuer,
                                           subject=self.subject,
                                           audience=self.audience,
                                           body=self.body)
        r = Request('https://a.b', body=body)
        self.assertEqual(r.isnot, 'empty') 
        self.assertEqual(r.grant_type, ServiceApplicationClient.grant_type) 

        key = RSA.importKey(self.private_key).publickey()
        claim = jwt.decode(r.assertion, key)

        self.assertEqual(claim['iss'], self.issuer)
        self.assertEqual(claim['aud'], self.audience)
        self.assertEqual(claim['sub'], self.subject)
        self.assertEqual(claim['iat'], int(t.return_value))

    @patch('time.time')
    def test_parse_token_response(self, t):
        t.return_value = time()
        self.token['expires_at'] = self.token['expires_in'] + t.return_value

        client = ServiceApplicationClient(self.client_id)

        # Parse code and state
        response = client.parse_request_body_response(self.token_json, scope=self.scope)
        self.assertEqual(response, self.token)
        self.assertEqual(client.access_token, response.get("access_token"))
        self.assertEqual(client.refresh_token, response.get("refresh_token"))
        self.assertEqual(client.token_type, response.get("token_type"))

        # Mismatching state
        self.assertRaises(Warning, client.parse_request_body_response, self.token_json, scope="invalid")
        os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '2'
        token = client.parse_request_body_response(self.token_json, scope="invalid")
        self.assertTrue(token.scope_changed)
        del os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE']

