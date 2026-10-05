from unittest import mock
from urllib.parse import urlencode

from oauthlib.oauth2 import InvalidRequestError
from oauthlib.openid import RequestValidator, Server

from tests.unittest import TestCase


class ResponseTypeOrderingTest(TestCase):
    """Reordered response_type values must be handled like the registered
    spelling, including the mandatory hybrid nonce check (#986)."""

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = 'https://a.b/cb'
        self.validator.get_id_token.return_value = 'MOCKED_ID_TOKEN'
        self.validator.get_code_challenge.return_value = None
        # A validator comparing response_type values as sets would have
        # accepted reordered values and skipped the hybrid nonce check.
        self.validator.validate_response_type.side_effect = (
            lambda client_id, response_type, client, request:
            set(response_type.split()) in ({'code', 'id_token'},
                                           {'code', 'id_token', 'token'}))
        self.server = Server(self.validator)

    def uri(self, response_type, **extra):
        params = {
            'client_id': 'abcdef',
            'response_type': response_type,
            'redirect_uri': 'https://a.b/cb',
            'scope': 'openid',
            'state': 'abc',
        }
        params.update(extra)
        return 'https://a.b/auth?' + urlencode(params)

    def authorize(self, response_type, **extra):
        h, b, s = self.server.create_authorization_response(
            self.uri(response_type, **extra), scopes=['openid'])
        self.assertIsNone(b)
        self.assertEqual(s, 302)
        return h['Location']

    def test_reordered_hybrid_requires_nonce(self):
        for response_type in ('id_token code', 'token id_token code',
                              'id_token token code'):
            with self.subTest(response_type=response_type):
                location = self.authorize(response_type)
                self.assertIn('error=invalid_request', location)
                self.assertIn('nonce', location)

    def test_reordered_hybrid_validate_requires_nonce(self):
        with self.assertRaises(InvalidRequestError):
            self.server.validate_authorization_request(self.uri('id_token code'))

    def test_reordered_hybrid_is_normalized(self):
        location = self.authorize('id_token code', nonce='xyz')
        self.assertIn('#code=', location)
        self.assertIn('id_token=MOCKED_ID_TOKEN', location)
        self.assertNotIn('access_token=', location)
        response_type = self.validator.validate_response_type.call_args[0][1]
        self.assertEqual(response_type, 'code id_token')

    def test_reordered_hybrid_token_is_normalized(self):
        location = self.authorize('token id_token code', nonce='xyz')
        self.assertIn('#code=', location)
        self.assertIn('access_token=', location)
        self.assertIn('id_token=MOCKED_ID_TOKEN', location)
        response_type = self.validator.validate_response_type.call_args[0][1]
        self.assertEqual(response_type, 'code id_token token')
