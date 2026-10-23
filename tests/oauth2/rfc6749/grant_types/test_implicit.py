# -*- coding: utf-8 -*-
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import ImplicitGrant
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase


class ImplicitGrantTest(TestCase):

    def setUp(self):
        mock_client = mock.MagicMock()
        mock_client.user.return_value = 'mocked user'
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.client = mock_client
        self.request.client_id = 'abcdef'
        self.request.response_type = 'token'
        self.request.state = 'xyz'
        self.request.redirect_uri = 'https://b.c/p'

        self.mock_validator = mock.MagicMock()
        self.auth = ImplicitGrant(request_validator=self.mock_validator)

    @mock.patch('oauthlib.common.generate_token')
    def test_create_token_response(self, generate_token):
        generate_token.return_value = '1234'
        bearer = BearerToken(self.mock_validator, expires_in=1800)
        h, _b, s = self.auth.create_token_response(self.request, bearer)
        correct_uri = 'https://b.c/p#access_token=1234&token_type=Bearer&expires_in=1800&state=xyz&scope=hello+world'
        self.assertEqual(s, 302)
        self.assertURLEqual(h['Location'], correct_uri, parse_fragment=True)
        self.assertEqual(self.mock_validator.save_token.call_count, 1)

        correct_uri = 'https://b.c/p?access_token=1234&token_type=Bearer&expires_in=1800&state=xyz&scope=hello+world'
        self.request.response_mode = 'query'
        h, _b, s = self.auth.create_token_response(self.request, bearer)
        self.assertURLEqual(h['Location'], correct_uri)

    def test_custom_validators(self):
        self.authval1, self.authval2 = mock.Mock(), mock.Mock()
        self.tknval1, self.tknval2 = mock.Mock(), mock.Mock()
        for val in (self.authval1, self.authval2):
            val.return_value = {}
        for val in (self.tknval1, self.tknval2):
            val.return_value = None
        self.auth.custom_validators.pre_token.append(self.tknval1)
        self.auth.custom_validators.post_token.append(self.tknval2)
        self.auth.custom_validators.pre_auth.append(self.authval1)
        self.auth.custom_validators.post_auth.append(self.authval2)

        bearer = BearerToken(self.mock_validator)
        self.auth.create_token_response(self.request, bearer)
        self.assertTrue(self.tknval1.called)
        self.assertTrue(self.tknval2.called)
        self.assertTrue(self.authval1.called)
        self.assertTrue(self.authval2.called)

    def test_error_response(self):
        self.mock_validator.validate_scopes.return_value = False
        bearer = BearerToken(self.mock_validator)

        # Errors default to the fragment response mode, both when the
        # provider redirects using in_uri() and in create_token_response.
        with self.assertRaises(errors.InvalidScopeError) as cm:
            self.auth.validate_authorization_request(self.request)
        self.assertIn('#error=invalid_scope',
                      cm.exception.in_uri(self.request.redirect_uri))

        self.request.response_mode = None
        h, _b, s = self.auth.create_token_response(self.request, bearer)
        self.assertEqual(s, 302)
        self.assertIn('#error=invalid_scope', h['Location'])
        self.assertNotIn('?error=', h['Location'])

    def test_unsupported_response_mode(self):
        self.request.response_mode = 'not-a-mode'
        bearer = BearerToken(self.mock_validator)
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.validate_authorization_request, self.request)
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_token_response, self.request, bearer)
        self.assertFalse(self.mock_validator.validate_response_type.called)

    def test_response_mode_set_by_failing_pre_auth_validator(self):
        def set_response_mode(request):
            request.response_mode = 'form_post'
            raise errors.InvalidRequestError(request=request)
        self.auth.custom_validators.pre_auth.append(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        with self.assertRaises(errors.UnsupportedResponseModeError) as cm:
            self.auth.validate_authorization_request(self.request)
        # Not reported as raised while handling the normal error.
        self.assertIsNone(cm.exception.__context__)
        self.request.response_mode = None
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_token_response, self.request, bearer)

    def test_response_mode_set_by_post_auth_validator(self):
        def set_response_mode(request):
            request.response_mode = 'form_post'
        self.auth.custom_validators.post_auth.append(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.validate_authorization_request, self.request)
        self.request.response_mode = None
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_token_response, self.request, bearer)
        self.assertFalse(self.mock_validator.save_token.called)

    def test_default_response_mode(self):
        self.auth.validate_authorization_request(self.request)
        self.assertEqual(self.request.response_mode, self.auth.default_response_mode)

    def test_error_without_request_gets_response_mode(self):
        def fail(request):
            raise errors.InvalidRequestError()
        self.auth.custom_validators.post_auth.append(fail)

        with self.assertRaises(errors.InvalidRequestError) as cm:
            self.auth.validate_authorization_request(self.request)
        self.assertEqual(cm.exception.response_mode, self.auth.default_response_mode)

    def test_response_mode_set_by_pre_auth_validator(self):
        def set_response_mode(request):
            request.response_mode = 'form_post'
            return {}
        self.auth.custom_validators.pre_auth.append(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.validate_authorization_request, self.request)
        self.request.response_mode = None
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_token_response, self.request, bearer)
        self.assertFalse(self.mock_validator.save_token.called)

    def test_response_mode_set_by_failing_post_auth_validator(self):
        def set_response_mode(request):
            request.response_mode = 'form_post'
            raise errors.InvalidRequestError(request=request)
        self.auth.custom_validators.post_auth.append(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.validate_authorization_request, self.request)
        self.request.response_mode = None
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_token_response, self.request, bearer)

    def test_response_mode_set_by_token_modifier(self):
        def set_response_mode(token, token_handler, request):
            request.response_mode = 'form_post'
            return token
        self.auth.register_token_modifier(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_token_response, self.request, bearer)
        self.assertFalse(self.mock_validator.save_token.called)


class CustomDefaultResponseModeTest(TestCase):
    """A subclass may support another response mode as its default."""

    class FormPostGrant(ImplicitGrant):
        default_response_mode = 'form_post'

        def prepare_authorization_response(self, request, token, headers, body, status):
            if request.response_mode == 'form_post':
                return headers, 'form_post:%s' % token['access_token'], 200
            return super().prepare_authorization_response(
                request, token, headers, body, status)

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.auth = self.FormPostGrant(request_validator=self.mock_validator)
        self.bearer = BearerToken(self.mock_validator)
        self.request = Request('http://a.b/path')
        self.request.client_id = 'abcdef'
        self.request.response_type = 'token'
        self.request.redirect_uri = 'https://b.c/p'

    @mock.patch('oauthlib.common.generate_token')
    def test_default_response_mode(self, generate_token):
        generate_token.return_value = '1234'
        _h, b, s = self.auth.create_token_response(self.request, self.bearer)
        self.assertEqual((b, s), ('form_post:1234', 200))

    def test_error_response(self):
        # Errors are still returned in the fragment, not the query.
        self.mock_validator.validate_scopes.return_value = False
        h, _b, s = self.auth.create_token_response(self.request, self.bearer)
        self.assertEqual(s, 302)
        self.assertIn('#error=invalid_scope', h['Location'])
