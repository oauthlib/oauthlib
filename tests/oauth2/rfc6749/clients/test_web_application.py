# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import datetime
import os

from mock import patch

from oauthlib import common, signals
from oauthlib.oauth2.rfc6749 import utils, errors
from oauthlib.oauth2 import Client
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2 import MobileApplicationClient
from oauthlib.oauth2 import LegacyApplicationClient
from oauthlib.oauth2 import BackendApplicationClient
from oauthlib.oauth2.rfc6749.clients import AUTH_HEADER, URI_QUERY, BODY

from ....unittest import TestCase


@patch('time.time', new=lambda: 1000)
class WebApplicationClientTest(TestCase):

    client_id = "someclientid"
    uri = "https://example.com/path?query=world"
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
    uri_authorize_code = uri_redirect + "&scope=%2Fprofile&state=" + state

    code = "zzzzaaaa"
    body = "not=empty"

    body_code = "not=empty&grant_type=authorization_code&code=%s&client_id=%s" % (code, client_id)
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
        "expires_at": 4600,
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

        # With extra parameters through kwargs
        uri = client.prepare_request_uri(self.uri, **self.kwargs)
        self.assertURLEqual(uri, self.uri_kwargs)

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

        # With extra parameters
        body = client.prepare_request_body(body=self.body, **self.kwargs)
        self.assertFormBodyEqual(body, self.body_kwargs)

    def test_parse_grant_uri_response(self):
        client = WebApplicationClient(self.client_id)

        # Parse code and state
        response = client.parse_request_uri_response(self.response_uri, state=self.state)
        self.assertEqual(response, self.response)
        self.assertEqual(client.code, self.code)

        # Mismatching state
        self.assertRaises(errors.MismatchingStateError,
                client.parse_request_uri_response,
                self.response_uri,
                state="invalid")

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
        os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
        token = client.parse_request_body_response(self.token_json, scope="invalid")
        self.assertTrue(token.scope_changed)

        scope_changes_recorded = []
        def record_scope_change(sender, message, old, new):
            scope_changes_recorded.append((message, old, new))

        signals.scope_changed.connect(record_scope_change)
        try:
            client.parse_request_body_response(self.token_json, scope="invalid")
            self.assertEqual(len(scope_changes_recorded), 1)
            message, old, new = scope_changes_recorded[0]
            self.assertEqual(message, 'Scope has changed from "invalid" to "/profile".')
            self.assertEqual(old, ['invalid'])
            self.assertEqual(new, ['/profile'])
        finally:
            signals.scope_changed.disconnect(record_scope_change)
        del os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE']

    def test_prepare_authorization_requeset(self):
        client = WebApplicationClient(self.client_id)

        url, header, body = client.prepare_authorization_request(
            self.uri, redirect_url=self.redirect_uri, state=self.state, scope=self.scope)
        self.assertURLEqual(url, self.uri_authorize_code)
        # verify default header and body only
        self.assertEqual(header, {'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(body, '')
