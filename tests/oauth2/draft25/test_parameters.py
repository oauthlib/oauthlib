from __future__ import absolute_import

from ...unittest import TestCase
from oauthlib.oauth2.draft25.parameters import *


class ParameterTests(TestCase):

    auth_grant = {
        u'uri': u'http://server.example.com/authorize',
        u'client_id': u's6BhdRkqt3',
        u'response_type': u'code',
        u'redirect_uri': u'https://client.example.com/cb',
        u'scope': u'photos',
        u'state': u'xyz'
    }
    auth_grant_uri = (u'http://server.example.com/authorize?response_type=code'
                      u'&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2F'
                      u'client.example.com%2Fcb&scope=photos&state=xyz')

    auth_implicit = {
        u'uri': u'http://server.example.com/authorize',
        u'client_id': u's6BhdRkqt3',
        u'response_type': u'token',
        u'redirect_uri': u'https://client.example.com/cb',
        u'state': u'xyz',
        u'extra': u'extra'
    }
    auth_implicit_uri = (u'http://server.example.com/authorize?'
                         u'response_type=token&client_id=s6BhdRkqt3&'
                         u'redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&'
                         u'state=xyz&extra=extra')

    grant_body = {
        u'grant_type': u'authorization_code',
        u'code': u'SplxlOBeZQQYbYS6WxSbIA',
        u'redirect_uri': u'https://client.example.com/cb'
    }
    auth_grant_body = (u'grant_type=authorization_code&'
                       u'code=SplxlOBeZQQYbYS6WxSbIA&'
                       u'redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb')

    pwd_body = {
        u'grant_type': u'password',
        u'username': u'johndoe',
        u'password': u'A3ddj3w'
    }
    password_body = u'grant_type=password&username=johndoe&password=A3ddj3w'

    cred_grant = {
        u'grant_type': u'client_credentials'
    }
    cred_body = u'grant_type=client_credentials'

    grant_response = u'https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz'

    grant_dict = {
        u'code': u'SplxlOBeZQQYbYS6WxSbIA',
        u'state': u'xyz'
    }

    error_nocode = u'https://client.example.com/cb?state=xyz'
    error_nostate = u'https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA'
    error_wrongstate = u'https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=abc'
    error_response = u'https://client.example.com/cb?error=access_denied&state=xyz'

    state = u'xyz'

    implicit_response = (u'http://example.com/cb#access_token=2YotnFZFEjr1zCsi'
                         u'cMWpAA&state=xyz&token_type=example&expires_in=3600')
    implicit_notoken = (u'http://example.com/cb#state=xyz&token_type=example&'
                        u'expires_in=3600')
    implicit_notype = (u'http://example.com/cb#access_token=2YotnFZFEjr1zCsicM'
                       u'WpAA&state=xyz&expires_in=3600')
    implicit_nostate = (u'http://example.com/cb#access_token=2YotnFZFEjr1zCsic'
                        u'MWpAA&token_type=example&expires_in=3600')
    implicit_wrongstate = (u'http://example.com/cb#access_token=2YotnFZFEjr1zC'
                           u'sicMWpAA&state=abc&token_type=example&expires_in=3600')

    implicit_dict = {
        u'access_token': u'2YotnFZFEjr1zCsicMWpAA',
        u'state': u'xyz',
        u'token_type': 'example',
        u'expires_in': u'3600',
    }

    json_response = (u'{ "access_token": "2YotnFZFEjr1zCsicMWpAA",'
                     u'  "token_type": "example",'
                     u'  "expires_in": 3600,'
                     u'  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                     u'  "example_parameter": "example_value",'
                     u'  "scope":"abc"}')

    json_error = u'{ "error": "invalid_request" }'

    json_notoken = (u'{ "token_type": "example",'
                    u'  "expires_in": 3600,'
                    u'  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                    u'  "example_parameter": "example_value" }')

    json_notype = (u'{  "access_token": "2YotnFZFEjr1zCsicMWpAA",'
                   u'   "expires_in": 3600,'
                   u'   "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                   u'   "example_parameter": "example_value" }')

    json_dict = {
       u'access_token': u'2YotnFZFEjr1zCsicMWpAA',
       u'token_type': u'example',
       u'expires_in': 3600,
       u'refresh_token': u'tGzv3JOkF0XG5Qx2TlKWIA',
       u'example_parameter': u'example_value',
       u'scope': u'abc'
    }

    def test_prepare_grant_uri(self):
        """Verify correct authorization URI construction."""
        self.assertEqual(prepare_grant_uri(**self.auth_grant), self.auth_grant_uri)
        self.assertEqual(prepare_grant_uri(**self.auth_implicit), self.auth_implicit_uri)

    def test_prepare_token_request(self):
        """Verify correct access token request body construction."""
        self.assertEqual(prepare_token_request(**self.grant_body), self.auth_grant_body)
        self.assertEqual(prepare_token_request(**self.pwd_body), self.password_body)
        self.assertEqual(prepare_token_request(**self.cred_grant), self.cred_body)

    def test_grant_response(self):
        """Verify correct parameter parsing and validation for auth code responses."""
        params = parse_authorization_code_response(self.grant_response)
        self.assertEqual(params, self.grant_dict)
        params = parse_authorization_code_response(self.grant_response, state=self.state)
        self.assertEqual(params, self.grant_dict)

        self.assertRaises(KeyError, parse_authorization_code_response,
                self.error_nocode)
        self.assertRaises(KeyError, parse_authorization_code_response,
                self.error_response)
        self.assertRaises(ValueError, parse_authorization_code_response,
                self.error_nostate, state=self.state)
        self.assertRaises(ValueError, parse_authorization_code_response,
                self.error_wrongstate, state=self.state)

    def test_implicit_token_response(self):
        """Verify correct parameter parsing and validation for implicit responses."""
        self.assertEqual(parse_implicit_response(self.implicit_response),
                self.implicit_dict)
        self.assertRaises(KeyError, parse_implicit_response,
                self.implicit_notoken)
        self.assertRaises(KeyError, parse_implicit_response,
                self.implicit_notype)
        self.assertRaises(ValueError, parse_implicit_response,
                self.implicit_nostate, state=self.state)
        self.assertRaises(ValueError, parse_implicit_response,
                self.implicit_wrongstate, state=self.state)

    def test_json_token_response(self):
        """Verify correct parameter parsing and validation for token responses. """
        self.assertEqual(parse_token_response(self.json_response), self.json_dict)
        self.assertRaises(KeyError, parse_token_response, self.json_error)
        self.assertRaises(KeyError, parse_token_response, self.json_notoken)
        self.assertRaises(Warning, parse_token_response, self.json_response, scope=u'aaa')
