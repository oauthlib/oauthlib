from __future__ import absolute_import, unicode_literals

import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.tokens import (
    prepare_mac_header,
    prepare_bearer_headers,
    prepare_bearer_body,
    prepare_bearer_uri,
    BearerToken,
    JWTToken,
)

from ...unittest import TestCase


class TokenTest(TestCase):

    # MAC without body/payload or extension
    mac_plain = {
        'token': 'h480djs93hd8',
        'uri': 'http://example.com/resource/1?b=1&a=2',
        'key': '489dks293j39',
        'http_method': 'GET',
        'nonce': '264095:dj83hs9s',
        'hash_algorithm': 'hmac-sha-1'
    }
    auth_plain = {
        'Authorization': 'MAC id="h480djs93hd8", nonce="264095:dj83hs9s",'
        ' mac="SLDJd4mg43cjQfElUs3Qub4L6xE="'
    }

    # MAC with body/payload, no extension
    mac_body = {
        'token': 'jd93dh9dh39D',
        'uri': 'http://example.com/request',
        'key': '8yfrufh348h',
        'http_method': 'POST',
        'nonce': '273156:di3hvdf8',
        'hash_algorithm': 'hmac-sha-1',
        'body': 'hello=world%21'
    }
    auth_body = {
        'Authorization': 'MAC id="jd93dh9dh39D", nonce="273156:di3hvdf8",'
        ' bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=", mac="W7bdMZbv9UWOTadASIQHagZyirA="'
    }

    # MAC with body/payload and extension
    mac_both = {
        'token': 'h480djs93hd8',
        'uri': 'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q',
        'key': '489dks293j39',
        'http_method': 'GET',
        'nonce': '264095:7d8f3e4a',
        'hash_algorithm': 'hmac-sha-1',
        'body': 'Hello World!',
        'ext': 'a,b,c'
    }
    auth_both = {
        'Authorization': 'MAC id="h480djs93hd8", nonce="264095:7d8f3e4a",'
        ' bodyhash="Lve95gjOVATpfV8EL5X4nxwjKHE=", ext="a,b,c",'
        ' mac="Z3C2DojEopRDIC88/imW8Ez853g="'
    }

    # Bearer
    token = 'vF9dft4qmT'
    uri = 'http://server.example.com/resource'
    bearer_headers = {
        'Authorization': 'Bearer vF9dft4qmT'
    }
    fake_bearer_headers = [
        {'Authorization': 'Beaver vF9dft4qmT'},
        {'Authorization': 'BeavervF9dft4qmT'},
        {'Authorization': 'Beaver  vF9dft4qmT'},
        {'Authorization': 'BearerF9dft4qmT'},
        {'Authorization': 'Bearer vF9d ft4qmT'},
    ]
    valid_header_with_multiple_spaces = {'Authorization': 'Bearer  vF9dft4qmT'}
    bearer_body = 'access_token=vF9dft4qmT'
    bearer_uri = 'http://server.example.com/resource?access_token=vF9dft4qmT'

    def _mocked_validate_bearer_token(self, token, scopes, request):
        if not token:
            return False
        return True

    def test_prepare_mac_header(self):
        """Verify mac signatures correctness

        TODO: verify hmac-sha-256
        """
        self.assertEqual(prepare_mac_header(**self.mac_plain), self.auth_plain)
        self.assertEqual(prepare_mac_header(**self.mac_body), self.auth_body)
        self.assertEqual(prepare_mac_header(**self.mac_both), self.auth_both)

    def test_prepare_bearer_request(self):
        """Verify proper addition of bearer tokens to requests.

        They may be represented as query components in body or URI or
        in a Bearer authorization header.
        """
        self.assertEqual(prepare_bearer_headers(self.token), self.bearer_headers)
        self.assertEqual(prepare_bearer_body(self.token), self.bearer_body)
        self.assertEqual(prepare_bearer_uri(self.token, uri=self.uri), self.bearer_uri)

    def test_fake_bearer_is_not_validated(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token

        for fake_header in self.fake_bearer_headers:
            request = Request('/', headers=fake_header)
            result = BearerToken(request_validator=request_validator).validate_request(request)

            self.assertFalse(result)

    def test_header_with_multispaces_is_validated(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token

        request = Request('/', headers=self.valid_header_with_multiple_spaces)
        result = BearerToken(request_validator=request_validator).validate_request(request)

        self.assertTrue(result)

    def test_estimate_type_with_fake_header_returns_type_0(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token

        for fake_header in self.fake_bearer_headers:
            request = Request('/', headers=fake_header)
            result = BearerToken(request_validator=request_validator).estimate_type(request)

            if fake_header['Authorization'].count(' ') == 2 and \
               fake_header['Authorization'].split()[0] == 'Bearer':
                # If we're dealing with the header containing 2 spaces, it will be recognized
                # as a Bearer valid header, the token itself will be invalid by the way.
                self.assertEqual(result, 9)
            else:
                self.assertEqual(result, 0)


class JWTTokenTestCase(TestCase):
    fake_bearer_headers = [
        {'Authorization': 'Beaver vF9dft4qmT'},
        {'Authorization': 'BeavervF9dft4qmT'},
        {'Authorization': 'Beaver  vF9dft4qmT'},
        {'Authorization': 'BearerF9dft4qmT'},
        {'Authorization': 'Bearer vF9df t4qmT'},
    ]

    valid_header_with_multiple_spaces = {'Authorization': 'Bearer  vF9dft4qmT'}

    def _mocked_validate_bearer_token(self, token, scopes, request):
        if not token:
            return False
        return True

    def test_create_token_callable_expires_in(self):
        """
        Test retrieval of the expires in value by calling the callable expires_in property
        """

        expires_in_mock = mock.MagicMock()
        request_mock = mock.MagicMock()

        token = JWTToken(expires_in=expires_in_mock, request_validator=mock.MagicMock())
        token.create_token(request=request_mock)

        expires_in_mock.assert_called_once_with(request_mock)

    def test_create_token_non_callable_expires_in(self):
        """
        When a non callable expires in is set this should just be set to the request
        """

        expires_in_mock = mock.NonCallableMagicMock()
        request_mock = mock.MagicMock()

        token = JWTToken(expires_in=expires_in_mock, request_validator=mock.MagicMock())
        token.create_token(request=request_mock)

        self.assertFalse(expires_in_mock.called)
        self.assertEqual(request_mock.expires_in, expires_in_mock)

    def test_create_token_calls_get_id_token(self):
        """
        When create_token is called the call should be forwarded to the get_id_token on the token validator
        """
        request_mock = mock.MagicMock()

        with mock.patch('oauthlib.oauth2.rfc6749.request_validator.RequestValidator',
                        autospec=True) as RequestValidatorMock:

            request_validator = RequestValidatorMock()

            token = JWTToken(expires_in=mock.MagicMock(), request_validator=request_validator)
            token.create_token(request=request_mock)

            request_validator.get_jwt_bearer_token.assert_called_once_with(None, None, request_mock)

    def test_validate_request_token_from_headers(self):
        """
        Bearer token get retrieved from headers.
        """

        with mock.patch('oauthlib.common.Request', autospec=True) as RequestMock, \
                mock.patch('oauthlib.oauth2.rfc6749.request_validator.RequestValidator',
                           autospec=True) as RequestValidatorMock:
            request_validator_mock = RequestValidatorMock()

            token = JWTToken(request_validator=request_validator_mock)

            request = RequestMock('/uri')
            # Scopes is retrieved using the __call__ method which is not picked up correctly by mock.patch
            # with autospec=True
            request.scopes = mock.MagicMock()
            request.headers = {
                'Authorization': 'Bearer some-token-from-header'
            }

            token.validate_request(request=request)

            request_validator_mock.validate_jwt_bearer_token.assert_called_once_with('some-token-from-header',
                                                                             request.scopes,
                                                                             request)

    def test_validate_token_from_request(self):
        """
        Token get retrieved from request object.
        """

        with mock.patch('oauthlib.common.Request', autospec=True) as RequestMock, \
                mock.patch('oauthlib.oauth2.rfc6749.request_validator.RequestValidator',
                           autospec=True) as RequestValidatorMock:
            request_validator_mock = RequestValidatorMock()

            token = JWTToken(request_validator=request_validator_mock)

            request = RequestMock('/uri')
            # Scopes is retrieved using the __call__ method which is not picked up correctly by mock.patch
            # with autospec=True
            request.scopes = mock.MagicMock()
            request.access_token = 'some-token-from-request-object'
            request.headers = {}

            token.validate_request(request=request)

            request_validator_mock.validate_jwt_bearer_token.assert_called_once_with('some-token-from-request-object',
                                                                             request.scopes,
                                                                             request)

    def test_fake_bearer_is_not_validated(self):
        request_validator = mock.MagicMock()
        request_validator.validate_jwt_bearer_token = self._mocked_validate_bearer_token

        for fake_header in self.fake_bearer_headers:
            request = Request('/', headers=fake_header)
            result = JWTToken(request_validator=request_validator).validate_request(request)

            self.assertFalse(result)

    def test_header_with_multiple_spaces_is_validated(self):
        request_validator = mock.MagicMock()
        request_validator.validate_jwt_bearer_token = self._mocked_validate_bearer_token
        request = Request('/', headers=self.valid_header_with_multiple_spaces)
        result = JWTToken(request_validator=request_validator).validate_request(request)

        self.assertTrue(result)

    def test_estimate_type(self):
        """
        Estimate type results for a jwt token
        """

        def test_token(token, expected_result):
            with mock.patch('oauthlib.common.Request', autospec=True) as RequestMock:
                jwt_token = JWTToken()

                request = RequestMock('/uri')
                # Scopes is retrieved using the __call__ method which is not picked up correctly by mock.patch
                # with autospec=True
                request.headers = {
                    'Authorization': 'Bearer {}'.format(token)
                }

                result = jwt_token.estimate_type(request=request)

                self.assertEqual(result, expected_result)

        test_items = (
            ('eyfoo.foo.foo', 10),
            ('eyfoo.foo.foo.foo.foo', 10),
            ('eyfoobar', 0)
        )

        for token, expected_result in test_items:
            test_token(token, expected_result)
