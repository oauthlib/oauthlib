from unittest import mock

from oauthlib.oauth2.rfc6749.endpoints.authorization import (
    AuthorizationEndpoint,
)

from tests.unittest import TestCase


class ResponseTypeNormalizationTest(TestCase):
    """The order of space-delimited response_type values does not matter.

    See RFC 6749 section 3.1.1 and OAuth 2.0 Multiple Response Type
    Encoding Practices section 4.
    """

    def setUp(self):
        self.code = mock.MagicMock()
        self.hybrid = mock.MagicMock()
        self.hybrid_token = mock.MagicMock()
        self.endpoint = AuthorizationEndpoint(
            default_response_type='code',
            default_token_type=mock.MagicMock(),
            response_types={
                'code': self.code,
                'code id_token': self.hybrid,
                'code id_token token': self.hybrid_token,
            },
        )

    def uri(self, response_type):
        return ('https://a.b/auth?client_id=foo&response_type=%s'
                % response_type.replace(' ', '+'))

    def dispatched_request(self, handler, method):
        args = getattr(handler, method).call_args[0]
        return args[0]

    def test_registered_response_type_is_unchanged(self):
        self.endpoint.validate_authorization_request(self.uri('code id_token'))
        request = self.dispatched_request(self.hybrid, 'validate_authorization_request')
        self.assertEqual(request.response_type, 'code id_token')
        self.code.validate_authorization_request.assert_not_called()

    def test_reordered_response_type_is_normalized(self):
        for method in ('validate_authorization_request',
                       'create_authorization_response'):
            for response_type, handler, expected in (
                ('id_token code', self.hybrid, 'code id_token'),
                ('token code id_token', self.hybrid_token, 'code id_token token'),
                ('id_token token code', self.hybrid_token, 'code id_token token'),
            ):
                with self.subTest(method=method, response_type=response_type):
                    handler.reset_mock()
                    self.code.reset_mock()
                    getattr(self.endpoint, method)(self.uri(response_type))
                    request = self.dispatched_request(handler, method)
                    self.assertEqual(request.response_type, expected)
                    getattr(self.code, method).assert_not_called()

    def test_repeated_values_are_not_normalized(self):
        self.endpoint.validate_authorization_request(self.uri('id_token code code'))
        self.hybrid.validate_authorization_request.assert_not_called()
        request = self.dispatched_request(self.code, 'validate_authorization_request')
        self.assertEqual(request.response_type, 'id_token code code')

    def test_unregistered_values_are_not_normalized(self):
        self.endpoint.validate_authorization_request(self.uri('token code'))
        self.hybrid_token.validate_authorization_request.assert_not_called()
        request = self.dispatched_request(self.code, 'validate_authorization_request')
        self.assertEqual(request.response_type, 'token code')

    def test_missing_response_type(self):
        self.endpoint.validate_authorization_request('https://a.b/auth?client_id=foo')
        request = self.dispatched_request(self.code, 'validate_authorization_request')
        self.assertIsNone(request.response_type)
