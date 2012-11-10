# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from ...unittest import TestCase

import datetime
from oauthlib import common
from oauthlib.oauth2.draft25 import Client, PasswordCredentialsClient
from oauthlib.oauth2.draft25 import UserAgentClient, WebApplicationClient
from oauthlib.oauth2.draft25 import ClientCredentialsClient
from oauthlib.oauth2.draft25 import AUTH_HEADER, URI_QUERY, BODY


class ClientTest(TestCase):

    client_id = "someclientid"
    uri = "http://example.com/path?query=world"
    body = "not=empty"
    headers = {}
    access_token = "token"
    mac_key = "secret"

    bearer_query = uri + "&access_token=" + access_token
    bearer_header = {
        "Authorization": "Bearer " + access_token
    }
    bearer_body = body + "&access_token=" + access_token

    mac_00_header = {
        "Authorization": 'MAC id="' + access_token + '", nonce="0:abc123",' +
                         ' bodyhash="Yqyso8r3hR5Nm1ZFv+6AvNHrxjE=",' +
                         ' mac="khWygG6wFPnWeJteDP7aLOPgzZM="'
    }
    mac_01_header = {
        "Authorization": 'MAC id="' + access_token + '", ts="123456789",' +
                          ' nonce="abc123", mac="CoHLzBGb8zVNdLZQDA2tiO6mryk="'
    }

    def test_add_bearer_token(self):
        """Test a number of bearer token placements"""

        # Invalid token type
        client = Client(self.client_id, token_type="invalid")
        self.assertRaises(ValueError, client.add_token, self.uri)

        # Missing access token
        client = Client(self.client_id)
        self.assertRaises(ValueError, client.add_token, self.uri)

        # The default token placement, bearer in auth header
        client = Client(self.client_id, access_token=self.access_token)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers)
        self.assertURLEqual(uri, self.uri)
        self.assertFormBodyEqual(body, self.body)
        self.assertEqual(headers, self.bearer_header)

        # Setting default placements of tokens
        client = Client(self.client_id, access_token=self.access_token,
                default_token_placement=AUTH_HEADER)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers)
        self.assertURLEqual(uri, self.uri)
        self.assertFormBodyEqual(body, self.body)
        self.assertEqual(headers, self.bearer_header)

        client = Client(self.client_id, access_token=self.access_token,
                default_token_placement=URI_QUERY)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers)
        self.assertURLEqual(uri, self.bearer_query)
        self.assertFormBodyEqual(body, self.body)
        self.assertEqual(headers, self.headers)

        client = Client(self.client_id, access_token=self.access_token,
                default_token_placement=BODY)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers)
        self.assertURLEqual(uri, self.uri)
        self.assertFormBodyEqual(body, self.bearer_body)
        self.assertEqual(headers, self.headers)

        # Asking for specific placement in the add_token method
        client = Client(self.client_id, access_token=self.access_token)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers, token_placement=AUTH_HEADER)
        self.assertURLEqual(uri, self.uri)
        self.assertFormBodyEqual(body, self.body)
        self.assertEqual(headers, self.bearer_header)

        client = Client(self.client_id, access_token=self.access_token)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers, token_placement=URI_QUERY)
        self.assertURLEqual(uri, self.bearer_query)
        self.assertFormBodyEqual(body, self.body)
        self.assertEqual(headers, self.headers)

        client = Client(self.client_id, access_token=self.access_token)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers, token_placement=BODY)
        self.assertURLEqual(uri, self.uri)
        self.assertFormBodyEqual(body, self.bearer_body)
        self.assertEqual(headers, self.headers)

        # Invalid token placement
        client = Client(self.client_id, access_token=self.access_token)
        self.assertRaises(ValueError, client.add_token, self.uri, body=self.body,
                headers=self.headers, token_placement="invalid")

        client = Client(self.client_id, access_token=self.access_token,
                default_token_placement="invalid")
        self.assertRaises(ValueError, client.add_token, self.uri, body=self.body,
                headers=self.headers)

    def test_add_mac_token(self):
        # Missing access token
        client = Client(self.client_id, token_type="MAC")
        self.assertRaises(ValueError, client.add_token, self.uri)

        # Invalid hash algorithm
        client = Client(self.client_id, token_type="MAC",
                access_token=self.access_token, mac_key=self.mac_key,
                mac_algorithm="hmac-sha-2")
        self.assertRaises(ValueError, client.add_token, self.uri)

        orig_generate_timestamp = common.generate_timestamp
        orig_generate_nonce = common.generate_nonce
        self.addCleanup(setattr, common, 'generage_timestamp', orig_generate_timestamp)
        self.addCleanup(setattr, common, 'generage_nonce', orig_generate_nonce)
        common.generate_timestamp = lambda: '123456789'
        common.generate_nonce = lambda: 'abc123'

        # Add the Authorization header (draft 00)
        client = Client(self.client_id, token_type="MAC",
                access_token=self.access_token, mac_key=self.mac_key,
                mac_algorithm="hmac-sha-1")
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers, issue_time=datetime.datetime.now())
        self.assertEqual(uri, self.uri)
        self.assertEqual(body, self.body)
        self.assertEqual(headers, self.mac_00_header)

        # Add the Authorization header (draft 00)
        client = Client(self.client_id, token_type="MAC",
                access_token=self.access_token, mac_key=self.mac_key,
                mac_algorithm="hmac-sha-1")
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers, draft=1)
        self.assertEqual(uri, self.uri)
        self.assertEqual(body, self.body)
        self.assertEqual(headers, self.mac_01_header)


class WebApplicationClientTest(TestCase):

    client_id = "someclientid"
    uri = "http://example.com/path?query=world"
    uri_id = uri + "&response_type=code&client_id=" + client_id
    uri_redirect = uri_id + "&redirect_uri=http%3A%2F%2Fmy.page.com%2Fcallback"
    redirect_uri = "http://my.page.com/callback"
    scope = ["/profile"]
    state = "xyz"
    uri_scope = uri_id + "&scope=%2Fprofile"
    uri_state = uri_id + "&state=" + state
    kwargs = {
        "some": "providers",
        "require": "extra arguments"
    }
    uri_kwargs = uri_id + "&some=providers&require=extra+arguments"

    code = "zzzzaaaa"
    body = "not=empty"

    body_code = "not=empty&grant_type=authorization_code&code=" + code
    body_redirect = body_code + "&redirect_uri=http%3A%2F%2Fmy.page.com%2Fcallback"
    body_kwargs = body_code + "&some=providers&require=extra+arguments"

    response_uri = "https://client.example.com/cb?code=zzzzaaaa&state=xyz"
    response = {"code": "zzzzaaaa", "state": "xyz"}

    token_json = ('{   "access_token":"2YotnFZFEjr1zCsicMWpAA",'
                  '    "token_type":"example",'
                  '    "expires_in":3600,'
                  '    "scope":"/profile",'
                  '    "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",'
                  '    "example_parameter":"example_value"}')
    token = {
        "access_token": "2YotnFZFEjr1zCsicMWpAA",
        "token_type": "example",
        "expires_in": 3600,
        "scope": scope,
        "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
        "example_parameter": "example_value"
    }

    def test_auth_grant_uri(self):
        client = WebApplicationClient(self.client_id)

        # Basic, no extra arguments
        uri = client.prepare_request_uri(self.uri)
        self.assertURLEqual(uri, self.uri_id)

        # With redirection uri
        uri = client.prepare_request_uri(self.uri, redirect_uri=self.redirect_uri)
        self.assertURLEqual(uri, self.uri_redirect)

        # With scope
        uri = client.prepare_request_uri(self.uri, scope=self.scope)
        self.assertURLEqual(uri, self.uri_scope)

        # With state
        uri = client.prepare_request_uri(self.uri, state=self.state)
        self.assertURLEqual(uri, self.uri_state)

        # With extra parameters through kwargs, checking using len since order
        # of dict items is undefined
        uri = client.prepare_request_uri(self.uri, **self.kwargs)
        self.assertEqual(len(uri), len(self.uri_kwargs))

    def test_request_body(self):
        client = WebApplicationClient(self.client_id, code=self.code)

        # Basic, no extra arguments
        body = client.prepare_request_body(body=self.body)
        self.assertFormBodyEqual(body, self.body_code)

        rclient = WebApplicationClient(self.client_id)
        body = rclient.prepare_request_body(code=self.code, body=self.body)
        self.assertFormBodyEqual(body, self.body_code)

        # With redirection uri
        body = client.prepare_request_body(body=self.body, redirect_uri=self.redirect_uri)
        self.assertFormBodyEqual(body, self.body_redirect)

        # With extra parameters, checked using length since order of
        # dict items is undefined
        body = client.prepare_request_body(body=self.body, **self.kwargs)
        self.assertEqual(len(body), len(self.body_kwargs))

    def test_parse_grant_uri_response(self):
        client = WebApplicationClient(self.client_id)

        # Parse code and state
        response = client.parse_request_uri_response(self.response_uri, state=self.state)
        self.assertEqual(response, self.response)
        self.assertEqual(client.code, self.code)

        # Mismatching state
        self.assertRaises(ValueError, client.parse_request_uri_response, self.response_uri, state="invalid")

    def test_parse_token_response(self):
        client = WebApplicationClient(self.client_id)

        # Parse code and state
        response = client.parse_request_body_response(self.token_json, scope=self.scope)
        self.assertEqual(response, self.token)
        self.assertEqual(client.access_token, response.get("access_token"))
        self.assertEqual(client.refresh_token, response.get("refresh_token"))
        self.assertEqual(client.token_type, response.get("token_type"))

        # Mismatching state
        self.assertRaises(Warning, client.parse_request_body_response, self.token_json, scope="invalid")


class UserAgentClientTest(TestCase):

    client_id = "someclientid"
    uri = "http://example.com/path?query=world"
    uri_id = uri + "&response_type=token&client_id=" + client_id
    uri_redirect = uri_id + "&redirect_uri=http%3A%2F%2Fmy.page.com%2Fcallback"
    redirect_uri = "http://my.page.com/callback"
    scope = ["/profile"]
    state = "xyz"
    uri_scope = uri_id + "&scope=%2Fprofile"
    uri_state = uri_id + "&state=" + state
    kwargs = {
        "some": "providers",
        "require": "extra arguments"
    }
    uri_kwargs = uri_id + "&some=providers&require=extra+arguments"

    code = "zzzzaaaa"

    response_uri = ('https://client.example.com/cb?#'
                    'access_token=2YotnFZFEjr1zCsicMWpAA&'
                    'token_type=example&'
                    'expires_in=3600&'
                    'scope=%2Fprofile&'
                    'example_parameter=example_value')
    token = {
        "access_token": "2YotnFZFEjr1zCsicMWpAA",
        "token_type": "example",
        "expires_in": "3600",
        "scope": scope,
        "example_parameter": "example_value"
    }

    def test_implicit_token_uri(self):
        client = UserAgentClient(self.client_id)

        # Basic, no extra arguments
        uri = client.prepare_request_uri(self.uri)
        self.assertURLEqual(uri, self.uri_id)

        # With redirection uri
        uri = client.prepare_request_uri(self.uri, redirect_uri=self.redirect_uri)
        self.assertURLEqual(uri, self.uri_redirect)

        # With scope
        uri = client.prepare_request_uri(self.uri, scope=self.scope)
        self.assertURLEqual(uri, self.uri_scope)

        # With state
        uri = client.prepare_request_uri(self.uri, state=self.state)
        self.assertURLEqual(uri, self.uri_state)

        # With extra parameters through kwargs, checking using len since order
        # of dict items is undefined
        uri = client.prepare_request_uri(self.uri, **self.kwargs)
        self.assertEqual(len(uri), len(self.uri_kwargs))

    def test_parse_token_response(self):
        client = UserAgentClient(self.client_id)

        # Parse code and state
        response = client.parse_request_uri_response(self.response_uri, scope=self.scope)
        self.assertEqual(response, self.token)
        self.assertEqual(client.access_token, response.get("access_token"))
        self.assertEqual(client.refresh_token, response.get("refresh_token"))
        self.assertEqual(client.token_type, response.get("token_type"))

        # Mismatching scope
        self.assertRaises(Warning, client.parse_request_uri_response, self.response_uri, scope="invalid")


class PasswordCredentialsClientTest(TestCase):

    client_id = "someclientid"
    scope = ["/profile"]
    kwargs = {
        "some": "providers",
        "require": "extra arguments"
    }

    username = "foo"
    password = "bar"
    body = "not=empty"

    body_up = "not=empty&grant_type=password&username=%s&password=%s" % (username, password)
    body_kwargs = body_up + "&some=providers&require=extra+arguments"

    token_json = ('{   "access_token":"2YotnFZFEjr1zCsicMWpAA",'
                  '    "token_type":"example",'
                  '    "expires_in":3600,'
                  '    "scope":"/profile",'
                  '    "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",'
                  '    "example_parameter":"example_value"}')
    token = {
        "access_token": "2YotnFZFEjr1zCsicMWpAA",
        "token_type": "example",
        "expires_in": 3600,
        "scope": scope,
        "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
        "example_parameter": "example_value"
    }

    def test_request_body(self):
        client = PasswordCredentialsClient(self.client_id, self.username,
                    self.password)

        # Basic, no extra arguments
        body = client.prepare_request_body(body=self.body)
        self.assertFormBodyEqual(body, self.body_up)

        # With extra parameters, checked using length since order of
        # dict items is undefined
        body = client.prepare_request_body(body=self.body, **self.kwargs)
        self.assertEqual(len(body), len(self.body_kwargs))

    def test_parse_token_response(self):
        client = PasswordCredentialsClient(self.client_id, self.username,
                self.password)

        # Parse code and state
        response = client.parse_request_body_response(self.token_json, scope=self.scope)
        self.assertEqual(response, self.token)
        self.assertEqual(client.access_token, response.get("access_token"))
        self.assertEqual(client.refresh_token, response.get("refresh_token"))
        self.assertEqual(client.token_type, response.get("token_type"))

        # Mismatching state
        self.assertRaises(Warning, client.parse_request_body_response, self.token_json, scope="invalid")


class ClientCredentialsClientTest(TestCase):

    client_id = "someclientid"
    scope = ["/profile"]
    kwargs = {
        "some": "providers",
        "require": "extra arguments"
    }

    body = "not=empty"

    body_up = "not=empty&grant_type=client_credentials"
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

    def test_request_body(self):
        client = ClientCredentialsClient(self.client_id)

        # Basic, no extra arguments
        body = client.prepare_request_body(body=self.body)
        self.assertFormBodyEqual(body, self.body_up)

        rclient = ClientCredentialsClient(self.client_id)
        body = rclient.prepare_request_body(body=self.body)
        self.assertFormBodyEqual(body, self.body_up)

        # With extra parameters, checked using length since order of
        # dict items is undefined
        body = client.prepare_request_body(body=self.body, **self.kwargs)
        self.assertEqual(len(body), len(self.body_kwargs))

    def test_parse_token_response(self):
        client = ClientCredentialsClient(self.client_id)

        # Parse code and state
        response = client.parse_request_body_response(self.token_json, scope=self.scope)
        self.assertEqual(response, self.token)
        self.assertEqual(client.access_token, response.get("access_token"))
        self.assertEqual(client.refresh_token, response.get("refresh_token"))
        self.assertEqual(client.token_type, response.get("token_type"))

        # Mismatching state
        self.assertRaises(Warning, client.parse_request_body_response, self.token_json, scope="invalid")
