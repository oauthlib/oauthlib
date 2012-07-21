# -*- coding: utf-8 -*-
from __future__ import absolute_import
from ...unittest import TestCase

from oauthlib.oauth2.draft25 import Client, PasswordCredentialsClient
from oauthlib.oauth2.draft25 import UserAgentClient, WebApplicationClient
from oauthlib.oauth2.draft25 import ClientCredentialsClient
from oauthlib.oauth2.draft25 import AUTH_HEADER, URI_QUERY, BODY


class ClientTest(TestCase):

    client_id = u"someclientid"
    uri = u"http://example.com/path?query=world"
    body = u"not=empty"
    headers = {}
    access_token = u"token"

    bearer_query = uri + u"&access_token=" + access_token
    bearer_header = {
        u"Authorization": "Bearer " + access_token
    }
    bearer_body = body + "&access_token=" + access_token

    def test_add_bearer_token(self):
        """Test a number of bearer token placements"""

        # Invalid token type
        client = Client(self.client_id, token_type=u"invalid")
        self.assertRaises(ValueError, client.add_token, self.uri)

        # Missing access token
        client = Client(self.client_id)
        self.assertRaises(ValueError, client.add_token, self.uri)

        # The default token placement, bearer in auth header
        client = Client(self.client_id, access_token=self.access_token)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers)
        self.assertEqual(uri, self.uri)
        self.assertEqual(body, self.body)
        self.assertEqual(headers, self.bearer_header)

        # Setting default placements of tokens
        client = Client(self.client_id, access_token=self.access_token,
                default_token_placement=AUTH_HEADER)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers)
        self.assertEqual(uri, self.uri)
        self.assertEqual(body, self.body)
        self.assertEqual(headers, self.bearer_header)

        client = Client(self.client_id, access_token=self.access_token,
                default_token_placement=URI_QUERY)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers)
        self.assertEqual(uri, self.bearer_query)
        self.assertEqual(body, self.body)
        self.assertEqual(headers, self.headers)

        client = Client(self.client_id, access_token=self.access_token,
                default_token_placement=BODY)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers)
        self.assertEqual(uri, self.uri)
        self.assertEqual(body, self.bearer_body)
        self.assertEqual(headers, self.headers)

        # Asking for specific placement in the add_token method
        client = Client(self.client_id, access_token=self.access_token)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers, token_placement=AUTH_HEADER)
        self.assertEqual(uri, self.uri)
        self.assertEqual(body, self.body)
        self.assertEqual(headers, self.bearer_header)

        client = Client(self.client_id, access_token=self.access_token)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers, token_placement=URI_QUERY)
        self.assertEqual(uri, self.bearer_query)
        self.assertEqual(body, self.body)
        self.assertEqual(headers, self.headers)

        client = Client(self.client_id, access_token=self.access_token)
        uri, headers, body = client.add_token(self.uri, body=self.body,
                headers=self.headers, token_placement=BODY)
        self.assertEqual(uri, self.uri)
        self.assertEqual(body, self.bearer_body)
        self.assertEqual(headers, self.headers)

        # Invalid token placement
        client = Client(self.client_id, access_token=self.access_token)
        self.assertRaises(ValueError, client.add_token, self.uri, body=self.body,
                headers=self.headers, token_placement=u"invalid")

        client = Client(self.client_id, access_token=self.access_token,
                default_token_placement=u"invalid")
        self.assertRaises(ValueError, client.add_token, self.uri, body=self.body,
                headers=self.headers)


class WebApplicationClientTest(TestCase):

    client_id = u"someclientid"
    uri = u"http://example.com/path?query=world"
    uri_id = uri + u"&response_type=code&client_id=" + client_id
    uri_redirect = uri_id + u"&redirect_uri=http%3A%2F%2Fmy.page.com%2Fcallback"
    redirect_uri = u"http://my.page.com/callback"
    scope = [u"/profile"]
    state = u"xyz"
    uri_scope = uri_id + u"&scope=%2Fprofile"
    uri_state = uri_id + u"&state=" + state
    kwargs = {
        u"some": u"providers",
        u"require": u"extra arguments"
    }
    uri_kwargs = uri_id + u"&some=providers&require=extra+arguments"

    code = u"zzzzaaaa"
    body = u"not=empty"

    body_code = u"not=empty&grant_type=authorization_code&code=" + code
    body_redirect = body_code + "&redirect_uri=http%3A%2F%2Fmy.page.com%2Fcallback"
    body_kwargs = body_code + u"&some=providers&require=extra+arguments"

    response_uri = u"https://client.example.com/cb?code=zzzzaaaa&state=xyz"
    response = {u"code": u"zzzzaaaa", u"state": u"xyz"}

    token_json = (u'{   "access_token":"2YotnFZFEjr1zCsicMWpAA",'
                  u'    "token_type":"example",'
                  u'    "expires_in":3600,'
                  u'    "scope":"/profile",'
                  u'    "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",'
                  u'    "example_parameter":"example_value"}')
    token = {
        u"access_token": u"2YotnFZFEjr1zCsicMWpAA",
        u"token_type": u"example",
        u"expires_in": 3600,
        u"scope": scope,
        u"refresh_token": u"tGzv3JOkF0XG5Qx2TlKWIA",
        u"example_parameter": u"example_value"
    }

    def test_auth_grant_uri(self):
        client = WebApplicationClient(self.client_id)

        # Basic, no extra arguments
        uri = client.prepare_request_uri(self.uri)
        self.assertEqual(uri, self.uri_id)

        # With redirection uri
        uri = client.prepare_request_uri(self.uri, redirect_uri=self.redirect_uri)
        self.assertEqual(uri, self.uri_redirect)

        # With scope
        uri = client.prepare_request_uri(self.uri, scope=self.scope)
        self.assertEqual(uri, self.uri_scope)

        # With state
        uri = client.prepare_request_uri(self.uri, state=self.state)
        self.assertEqual(uri, self.uri_state)

        # With extra parameters through kwargs, checking using len since order
        # of dict items is undefined
        uri = client.prepare_request_uri(self.uri, **self.kwargs)
        self.assertEqual(len(uri), len(self.uri_kwargs))

    def test_request_body(self):
        client = WebApplicationClient(self.client_id, code=self.code)

        # Basic, no extra arguments
        body = client.prepare_request_body(body=self.body)
        self.assertEqual(body, self.body_code)

        rclient = WebApplicationClient(self.client_id)
        body = rclient.prepare_request_body(code=self.code, body=self.body)
        self.assertEqual(body, self.body_code)

        # With redirection uri
        body = client.prepare_request_body(body=self.body, redirect_uri=self.redirect_uri)
        self.assertEqual(body, self.body_redirect)

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
        self.assertRaises(ValueError, client.parse_request_uri_response, self.response_uri, state=u"invalid")

    def test_parse_token_response(self):
        client = WebApplicationClient(self.client_id)

        # Parse code and state
        response = client.parse_request_body_response(self.token_json, scope=self.scope)
        self.assertEqual(response, self.token)
        self.assertEqual(client.access_token, response.get(u"access_token"))
        self.assertEqual(client.refresh_token, response.get(u"refresh_token"))
        self.assertEqual(client.token_type, response.get(u"token_type"))

        # Mismatching state
        self.assertRaises(Warning, client.parse_request_body_response, self.token_json, scope=u"invalid")


class UserAgentClientTest(TestCase):

    client_id = u"someclientid"
    uri = u"http://example.com/path?query=world"
    uri_id = uri + u"&response_type=token&client_id=" + client_id
    uri_redirect = uri_id + u"&redirect_uri=http%3A%2F%2Fmy.page.com%2Fcallback"
    redirect_uri = u"http://my.page.com/callback"
    scope = [u"/profile"]
    state = u"xyz"
    uri_scope = uri_id + u"&scope=%2Fprofile"
    uri_state = uri_id + u"&state=" + state
    kwargs = {
        u"some": u"providers",
        u"require": u"extra arguments"
    }
    uri_kwargs = uri_id + u"&some=providers&require=extra+arguments"

    code = u"zzzzaaaa"

    response_uri = (u'https://client.example.com/cb?#'
                    u'access_token=2YotnFZFEjr1zCsicMWpAA&'
                    u'token_type=example&'
                    u'expires_in=3600&'
                    u'scope=%2Fprofile&'
                    u'example_parameter=example_value')
    token = {
        u"access_token": u"2YotnFZFEjr1zCsicMWpAA",
        u"token_type": u"example",
        u"expires_in": u"3600",
        u"scope": scope,
        u"example_parameter": u"example_value"
    }

    def test_implicit_token_uri(self):
        client = UserAgentClient(self.client_id)

        # Basic, no extra arguments
        uri = client.prepare_request_uri(self.uri)
        self.assertEqual(uri, self.uri_id)

        # With redirection uri
        uri = client.prepare_request_uri(self.uri, redirect_uri=self.redirect_uri)
        self.assertEqual(uri, self.uri_redirect)

        # With scope
        uri = client.prepare_request_uri(self.uri, scope=self.scope)
        self.assertEqual(uri, self.uri_scope)

        # With state
        uri = client.prepare_request_uri(self.uri, state=self.state)
        self.assertEqual(uri, self.uri_state)

        # With extra parameters through kwargs, checking using len since order
        # of dict items is undefined
        uri = client.prepare_request_uri(self.uri, **self.kwargs)
        self.assertEqual(len(uri), len(self.uri_kwargs))

    def test_parse_token_response(self):
        client = UserAgentClient(self.client_id)

        # Parse code and state
        response = client.parse_request_uri_response(self.response_uri, scope=self.scope)
        self.assertEqual(response, self.token)
        self.assertEqual(client.access_token, response.get(u"access_token"))
        self.assertEqual(client.refresh_token, response.get(u"refresh_token"))
        self.assertEqual(client.token_type, response.get(u"token_type"))

        # Mismatching scope
        self.assertRaises(Warning, client.parse_request_uri_response, self.response_uri, scope=u"invalid")


class PasswordCredentialsClientTest(TestCase):

    client_id = u"someclientid"
    scope = [u"/profile"]
    kwargs = {
        u"some": u"providers",
        u"require": u"extra arguments"
    }

    username = u"foo"
    password = u"bar"
    body = u"not=empty"

    body_up = u"not=empty&grant_type=password&username=%s&password=%s" % (username, password)
    body_kwargs = body_up + u"&some=providers&require=extra+arguments"

    token_json = (u'{   "access_token":"2YotnFZFEjr1zCsicMWpAA",'
                  u'    "token_type":"example",'
                  u'    "expires_in":3600,'
                  u'    "scope":"/profile",'
                  u'    "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",'
                  u'    "example_parameter":"example_value"}')
    token = {
        u"access_token": u"2YotnFZFEjr1zCsicMWpAA",
        u"token_type": u"example",
        u"expires_in": 3600,
        u"scope": scope,
        u"refresh_token": u"tGzv3JOkF0XG5Qx2TlKWIA",
        u"example_parameter": u"example_value"
    }

    def test_request_body(self):
        client = PasswordCredentialsClient(self.client_id, self.username,
                    self.password)

        # Basic, no extra arguments
        body = client.prepare_request_body(body=self.body)
        self.assertEqual(body, self.body_up)

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
        self.assertEqual(client.access_token, response.get(u"access_token"))
        self.assertEqual(client.refresh_token, response.get(u"refresh_token"))
        self.assertEqual(client.token_type, response.get(u"token_type"))

        # Mismatching state
        self.assertRaises(Warning, client.parse_request_body_response, self.token_json, scope=u"invalid")


class ClientCredentialsClientTest(TestCase):

    client_id = u"someclientid"
    scope = [u"/profile"]
    kwargs = {
        u"some": u"providers",
        u"require": u"extra arguments"
    }

    body = u"not=empty"

    body_up = u"not=empty&grant_type=client_credentials"
    body_kwargs = body_up + u"&some=providers&require=extra+arguments"

    token_json = (u'{   "access_token":"2YotnFZFEjr1zCsicMWpAA",'
                  u'    "token_type":"example",'
                  u'    "expires_in":3600,'
                  u'    "scope":"/profile",'
                  u'    "example_parameter":"example_value"}')
    token = {
        u"access_token": u"2YotnFZFEjr1zCsicMWpAA",
        u"token_type": u"example",
        u"expires_in": 3600,
        u"scope": [u"/profile"],
        u"example_parameter": u"example_value"
    }

    def test_request_body(self):
        client = ClientCredentialsClient(self.client_id)

        # Basic, no extra arguments
        body = client.prepare_request_body(body=self.body)
        self.assertEqual(body, self.body_up)

        rclient = ClientCredentialsClient(self.client_id)
        body = rclient.prepare_request_body(body=self.body)
        self.assertEqual(body, self.body_up)

        # With extra parameters, checked using length since order of
        # dict items is undefined
        body = client.prepare_request_body(body=self.body, **self.kwargs)
        self.assertEqual(len(body), len(self.body_kwargs))

    def test_parse_token_response(self):
        client = ClientCredentialsClient(self.client_id)

        # Parse code and state
        response = client.parse_request_body_response(self.token_json, scope=self.scope)
        self.assertEqual(response, self.token)
        self.assertEqual(client.access_token, response.get(u"access_token"))
        self.assertEqual(client.refresh_token, response.get(u"refresh_token"))
        self.assertEqual(client.token_type, response.get(u"token_type"))

        # Mismatching state
        self.assertRaises(Warning, client.parse_request_body_response, self.token_json, scope=u"invalid")
