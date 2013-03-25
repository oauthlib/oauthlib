
"""Test for the various oauth 2 provider endpoints.

The tests focus on shared functionality between the different endpoints to
ensure consistency in both behaviour and provided interfaces.
"""
from __future__ import absolute_import, unicode_literals
import json
import mock
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
from ...unittest import TestCase

from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import WebApplicationServer, MobileApplicationServer
from oauthlib.oauth2 import LegacyApplicationServer, BackendApplicationServer
from oauthlib.oauth2.draft25 import errors


def get_query_credentials(uri):
    return urlparse.parse_qs(urlparse.urlparse(uri).query,
            keep_blank_values=True)


def get_fragment_credentials(uri):
    return urlparse.parse_qs(urlparse.urlparse(uri).fragment,
            keep_blank_values=True)


class TestScopeHandling(TestCase):

    DEFAULT_REDIRECT_URI = 'http://i.b./path'

    def set_scopes(self, scopes):
        def set_request_scopes(client_id, code, client, request):
            request.scopes = scopes
            return True
        return set_request_scopes

    def set_user(self, request):
        request.user = 'foo'
        request.client_id = 'bar'
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = TestScopeHandling.DEFAULT_REDIRECT_URI
        self.validator.authenticate_client.side_effect = self.set_client
        self.web = WebApplicationServer(self.validator)
        self.mobile = MobileApplicationServer(self.validator)
        self.legacy = LegacyApplicationServer(self.validator)
        self.backend = BackendApplicationServer(self.validator)

    def test_scope_extraction(self):
        scopes = (
            ('images', ['images']),
            ('images+videos', ['images', 'videos']),
            ('http%3A%2f%2fa.b%2fvideos', ['http://a.b/videos']),
            ('http%3A%2f%2fa.b%2fvideos+pics', ['http://a.b/videos', 'pics']),
            ('pics+http%3A%2f%2fa.b%2fvideos', ['pics', 'http://a.b/videos']),
            ('http%3A%2f%2fa.b%2fvideos+https%3A%2f%2fc.d%2Fsecret', ['http://a.b/videos', 'https://c.d/secret']),
        )

        uri = 'http://example.com/path?client_id=abc&scope=%s&response_type=%s'
        for scope, correct_scopes in scopes:
            scopes, _ = self.web.validate_authorization_request(
                    uri % (scope, 'code'))
            self.assertItemsEqual(scopes, correct_scopes)
            scopes, _ = self.mobile.validate_authorization_request(
                    uri % (scope, 'token'))
            self.assertItemsEqual(scopes, correct_scopes)

    def test_scope_preservation(self):
        scope = 'pics+http%3A%2f%2fa.b%2fvideos'
        decoded_scope = 'pics http://a.b/videos'
        auth_uri = 'http://example.com/path?client_id=abc&response_type='
        token_uri = 'http://example.com/path'

        # authorization grant
        uri, _, _, _ = self.web.create_authorization_response(
                auth_uri + 'code', scopes=decoded_scope.split(' '))
        self.validator.validate_code.side_effect = self.set_scopes(decoded_scope.split(' '))
        code = get_query_credentials(uri)['code'][0]
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=%s' % code)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

        # implicit grant
        uri, _, _, _ = self.mobile.create_authorization_response(
                auth_uri + 'token', scopes=decoded_scope.split(' '))
        self.assertEqual(get_fragment_credentials(uri)['scope'][0], decoded_scope)

        # resource owner password credentials grant
        body = 'grant_type=password&username=abc&password=secret&scope=%s'
        _, _, body, _ = self.legacy.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

        # client credentials grant
        body = 'grant_type=client_credentials&scope=%s'
        self.validator.authenticate_client.side_effect = self.set_user
        _, _, body, _ = self.backend.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

    def test_scope_changed(self):
        scope = 'pics+http%3A%2f%2fa.b%2fvideos'
        scopes = ['images', 'http://a.b/videos']
        decoded_scope = 'images http://a.b/videos'
        auth_uri = 'http://example.com/path?client_id=abc&response_type='
        token_uri = 'http://example.com/path'

        # authorization grant
        uri, _, _, _ = self.web.create_authorization_response(
                auth_uri + 'code', scopes=scopes)
        code = get_query_credentials(uri)['code'][0]
        self.validator.validate_code.side_effect = self.set_scopes(scopes)
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=%s' % code)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

        # implicit grant
        self.validator.validate_scopes.side_effect = self.set_scopes(scopes)
        uri, _, _, _ = self.mobile.create_authorization_response(
                auth_uri + 'token', scopes=scopes)
        self.assertEqual(get_fragment_credentials(uri)['scope'][0], decoded_scope)

        # resource owner password credentials grant
        self.validator.validate_scopes.side_effect = self.set_scopes(scopes)
        body = 'grant_type=password&username=abc&password=secret&scope=%s'
        _, _, body, _ = self.legacy.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

        # client credentials grant
        self.validator.validate_scopes.side_effect = self.set_scopes(scopes)
        self.validator.authenticate_client.side_effect = self.set_user
        body = 'grant_type=client_credentials&scope=%s'
        _, _, body, _ = self.backend.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['scope'], decoded_scope)

    def test_invalid_scope(self):
        scope = 'pics+http%3A%2f%2fa.b%2fvideos'
        auth_uri = 'http://example.com/path?client_id=abc&response_type='
        token_uri = 'http://example.com/path'

        self.validator.validate_scopes.return_value = False

        # authorization grant
        uri, _, _, _ = self.web.create_authorization_response(
                auth_uri + 'code', scopes=['invalid'])
        error = get_query_credentials(uri)['error'][0]
        self.assertEqual(error, 'invalid_scope')

        # implicit grant
        uri, _, _, _ = self.mobile.create_authorization_response(
                auth_uri + 'token', scopes=['invalid'])
        error = get_fragment_credentials(uri)['error'][0]
        self.assertEqual(error, 'invalid_scope')

        # resource owner password credentials grant
        body = 'grant_type=password&username=abc&password=secret&scope=%s'
        _, _, body, _ = self.legacy.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['error'], 'invalid_scope')

        # client credentials grant
        self.validator.authenticate_client.side_effect = self.set_user
        body = 'grant_type=client_credentials&scope=%s'
        _, _, body, _ = self.backend.create_token_response(token_uri,
                body=body % scope)
        self.assertEqual(json.loads(body)['error'], 'invalid_scope')


class PreservationTest(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = TestScopeHandling.DEFAULT_REDIRECT_URI
        self.validator.authenticate_client.side_effect = self.set_client
        self.web = WebApplicationServer(self.validator)
        self.mobile = MobileApplicationServer(self.validator)

    def set_state(self, state):
        def set_request_state(client_id, code, client, request):
            request.state = state
            return True
        return set_request_state

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def test_state_preservation(self):
        auth_uri = 'http://example.com/path?state=xyz&client_id=abc&response_type='
        token_uri = 'http://example.com/path'

        # authorization grant
        uri, _, _, _ = self.web.create_authorization_response(
                auth_uri + 'code', scopes=['random'])
        code = get_query_credentials(uri)['code'][0]
        self.validator.validate_code.side_effect = self.set_state('xyz')
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=%s' % code)
        self.assertEqual(json.loads(body)['state'], 'xyz')

        # implicit grant
        uri, _, _, _ = self.mobile.create_authorization_response(
                auth_uri + 'token', scopes=['random'])
        self.assertEqual(get_fragment_credentials(uri)['state'][0], 'xyz')

    def test_redirect_uri_preservation(self):
        auth_uri = 'http://example.com/path?redirect_uri=http%3A%2F%2Fi.b%2Fpath&client_id=abc'
        redirect_uri = 'http://i.b/path'
        token_uri = 'http://example.com/path'

        # authorization grant
        uri, _, _, _ = self.web.create_authorization_response(
                auth_uri + '&response_type=code', scopes=['random'])
        self.assertTrue(uri.startswith(redirect_uri))

        # confirm_redirect_uri should return false if the redirect uri
        # was given in the authorization but not in the token request.
        self.validator.confirm_redirect_uri.return_value = False
        code = get_query_credentials(uri)['code'][0]
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=%s' % code)
        self.assertEqual(json.loads(body)['error'], 'access_denied')

        # implicit grant
        uri, _, _, _ = self.mobile.create_authorization_response(
                auth_uri + '&response_type=token', scopes=['random'])
        self.assertTrue(uri.startswith(redirect_uri))

    def test_invalid_redirect_uri(self):
        auth_uri = 'http://example.com/path?redirect_uri=http%3A%2F%2Fi.b%2Fpath&client_id=abc'
        self.validator.validate_redirect_uri.return_value = False

        # authorization grant
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.web.create_authorization_response,
                auth_uri + '&response_type=code', scopes=['random'])

        # implicit grant
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.mobile.create_authorization_response,
                auth_uri + '&response_type=token', scopes=['random'])

    def test_default_uri(self):
        auth_uri = 'http://example.com/path?state=xyz&client_id=abc'

        self.validator.get_default_redirect_uri.return_value = None

        # authorization grant
        self.assertRaises(errors.MissingRedirectURIError,
                self.web.create_authorization_response,
                auth_uri + '&response_type=code', scopes=['random'])

        # implicit grant
        self.assertRaises(errors.MissingRedirectURIError,
                self.mobile.create_authorization_response,
                auth_uri + '&response_type=token', scopes=['random'])


class ClientAuthenticationTest(TestCase):

    def inspect_client(self, request, refresh_token=False):
        if not request.client or not request.client.client_id:
            raise ValueError()
        return 'abc'

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = 'http://i.b./path'
        self.web = WebApplicationServer(self.validator,
                token_generator=self.inspect_client)
        self.mobile = MobileApplicationServer(self.validator,
                token_generator=self.inspect_client)
        self.legacy = LegacyApplicationServer(self.validator,
                token_generator=self.inspect_client)
        self.backend = BackendApplicationServer(self.validator,
                token_generator=self.inspect_client)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def set_client_id(self, client_id, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def set_username(self, username, password, client, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def test_client_id_authentication(self):
        token_uri = 'http://example.com/path'

        # authorization code grant
        self.validator.authenticate_client.return_value = False
        self.validator.authenticate_client_id.return_value = False
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=mock')
        self.assertEqual(json.loads(body)['error'], 'invalid_client')

        self.validator.authenticate_client_id.return_value = True
        self.validator.authenticate_client.side_effect = self.set_client
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=mock')
        self.assertIn('access_token', json.loads(body))

        # implicit grant
        auth_uri = 'http://example.com/path?client_id=abc&response_type=token'
        self.assertRaises(ValueError, self.mobile.create_authorization_response,
                auth_uri, scopes=['random'])

        self.validator.validate_client_id.side_effect = self.set_client_id
        uri, _, _, _ = self.mobile.create_authorization_response(auth_uri, scopes=['random'])
        self.assertIn('access_token', get_fragment_credentials(uri))

    def test_custom_authentication(self):
        token_uri = 'http://example.com/path'

        # authorization code grant
        self.assertRaises(NotImplementedError,
                self.web.create_token_response, token_uri,
                body='grant_type=authorization_code&code=mock')

        # password grant
        self.validator.authenticate_client.return_value = True
        self.assertRaises(NotImplementedError,
                self.legacy.create_token_response, token_uri,
                body='grant_type=password&username=abc&password=secret')

        # client credentials grant
        self.validator.authenticate_client.return_value = True
        self.assertRaises(NotImplementedError,
                self.backend.create_token_response, token_uri,
                body='grant_type=client_credentials')


class ResourceOwnerAssociationTest(TestCase):

    auth_uri = 'http://example.com/path?client_id=abc'
    token_uri = 'http://example.com/path'

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def set_user(self, client_id, code, client, request):
        request.user = 'test'
        return True

    def set_user_from_username(self, username, password, client, request):
        request.user = 'test'
        return True

    def set_user_from_credentials(self, request):
        request.user = 'test'
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def inspect_client(self, request, refresh_token=False):
        if not request.user:
            raise ValueError()
        return 'abc'

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = 'http://i.b./path'
        self.validator.authenticate_client.side_effect = self.set_client
        self.web = WebApplicationServer(self.validator,
                token_generator=self.inspect_client)
        self.mobile = MobileApplicationServer(self.validator,
                token_generator=self.inspect_client)
        self.legacy = LegacyApplicationServer(self.validator,
                token_generator=self.inspect_client)
        self.backend = BackendApplicationServer(self.validator,
                token_generator=self.inspect_client)

    def test_web_application(self):
        # TODO: code generator + intercept test
        uri, _, _, _ = self.web.create_authorization_response(
                self.auth_uri + '&response_type=code',
                credentials={'user': 'test'}, scopes=['random'])
        code = get_query_credentials(uri)['code'][0]
        self.assertRaises(ValueError,
                self.web.create_token_response, self.token_uri,
                body='grant_type=authorization_code&code=%s' % code)

        self.validator.validate_code.side_effect = self.set_user
        _, _, body, _ = self.web.create_token_response(self.token_uri,
                body='grant_type=authorization_code&code=%s' % code)
        self.assertEqual(json.loads(body)['access_token'], 'abc')

    def test_mobile_application(self):
        self.assertRaises(ValueError,
                self.mobile.create_authorization_response,
                self.auth_uri + '&response_type=token')

        uri, _, _, _ = self.mobile.create_authorization_response(
                self.auth_uri + '&response_type=token',
                credentials={'user': 'test'}, scopes=['random'])
        self.assertEqual(get_fragment_credentials(uri)['access_token'][0], 'abc')

    def test_legacy_application(self):
        body = 'grant_type=password&username=abc&password=secret'
        self.assertRaises(ValueError,
                self.legacy.create_token_response,
                self.token_uri, body=body)

        self.validator.validate_user.side_effect = self.set_user_from_username
        _, _, body, _ = self.legacy.create_token_response(
                self.token_uri, body=body)
        self.assertEqual(json.loads(body)['access_token'], 'abc')

    def test_backend_application(self):
        body = 'grant_type=client_credentials'
        self.assertRaises(ValueError,
                self.backend.create_token_response,
                self.token_uri, body=body)

        self.validator.authenticate_client.side_effect = self.set_user_from_credentials
        _, _, body, _ = self.backend.create_token_response(
                self.token_uri, body=body)
        self.assertEqual(json.loads(body)['access_token'], 'abc')


class ErrorResponseTest(TestCase):

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = None
        self.web = WebApplicationServer(self.validator)
        self.mobile = MobileApplicationServer(self.validator)
        self.legacy = LegacyApplicationServer(self.validator)
        self.backend = BackendApplicationServer(self.validator)

    def test_invalid_redirect_uri(self):
        uri = 'https://example.com/authorize?client_id=foo&redirect_uri=wrong'
        # Authorization code grant
        self.assertRaises(errors.InvalidRedirectURIError,
                self.web.validate_authorization_request, uri)
        self.assertRaises(errors.InvalidRedirectURIError,
                self.web.create_authorization_response, uri, scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.InvalidRedirectURIError,
                self.mobile.validate_authorization_request, uri)
        self.assertRaises(errors.InvalidRedirectURIError,
                self.mobile.create_authorization_response, uri, scopes=['foo'])

    def test_missing_redirect_uri(self):
        uri = 'https://example.com/authorize?client_id=foo'
        # Authorization code grant
        self.assertRaises(errors.MissingRedirectURIError,
                self.web.validate_authorization_request, uri)
        self.assertRaises(errors.MissingRedirectURIError,
                self.web.create_authorization_response, uri, scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.MissingRedirectURIError,
                self.mobile.validate_authorization_request, uri)
        self.assertRaises(errors.MissingRedirectURIError,
                self.mobile.create_authorization_response, uri, scopes=['foo'])

    def test_mismatching_redirect_uri(self):
        uri = 'https://example.com/authorize?client_id=foo&redirect_uri=https%3A%2F%2Fi.b%2Fback'
        # Authorization code grant
        self.validator.validate_redirect_uri.return_value = False
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.web.validate_authorization_request, uri)
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.web.create_authorization_response, uri, scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.mobile.validate_authorization_request, uri)
        self.assertRaises(errors.MismatchingRedirectURIError,
                self.mobile.create_authorization_response, uri, scopes=['foo'])

    def test_missing_client_id(self):
        uri = 'https://example.com/authorize?redirect_uri=https%3A%2F%2Fi.b%2Fback'
        # Authorization code grant
        self.validator.validate_redirect_uri.return_value = False
        self.assertRaises(errors.MissingClientIdError,
                self.web.validate_authorization_request, uri)
        self.assertRaises(errors.MissingClientIdError,
                self.web.create_authorization_response, uri, scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.MissingClientIdError,
                self.mobile.validate_authorization_request, uri)
        self.assertRaises(errors.MissingClientIdError,
                self.mobile.create_authorization_response, uri, scopes=['foo'])

    def test_invalid_client_id(self):
        uri = 'https://example.com/authorize?client_id=foo&redirect_uri=https%3A%2F%2Fi.b%2Fback'
        # Authorization code grant
        self.validator.validate_client_id.return_value = False
        self.assertRaises(errors.InvalidClientIdError,
                self.web.validate_authorization_request, uri)
        self.assertRaises(errors.InvalidClientIdError,
                self.web.create_authorization_response, uri, scopes=['foo'])

        # Implicit grant
        self.assertRaises(errors.InvalidClientIdError,
                self.mobile.validate_authorization_request, uri)
        self.assertRaises(errors.InvalidClientIdError,
                self.mobile.create_authorization_response, uri, scopes=['foo'])

    def test_invalid_request(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        token_uri = 'https://i.b/token'
        invalid_uris = [
            # Duplicate parameters
            'https://i.b/auth?client_id=foo&client_id=bar&response_type={0}',
            # Missing response type
            'https://i.b/auth?client_id=foo',
        ]

        # Authorization code grant
        for uri in invalid_uris:
            self.assertRaises(errors.InvalidRequestError,
                    self.web.validate_authorization_request,
                    uri.format('code'))
            url, _, _, _ = self.web.create_authorization_response(
                    uri.format('code'), scopes=['foo'])
            self.assertIn('error=invalid_request', url)
        invalid_bodies = [
            # duplicate params
            'grant_type=authorization_code&client_id=nope&client_id=nope&code=foo'
        ]
        for body in invalid_bodies:
            _, _, body, _ = self.web.create_token_response(token_uri,
                    body=body)
            self.assertEqual('invalid_request', json.loads(body)['error'])

        # Implicit grant
        for uri in invalid_uris:
            self.assertRaises(errors.InvalidRequestError,
                    self.mobile.validate_authorization_request,
                    uri.format('token'))
            url, _, _, _ = self.mobile.create_authorization_response(
                    uri.format('token'), scopes=['foo'])
            self.assertIn('error=invalid_request', url)

        # Password credentials grant
        invalid_bodies = [
            # duplicate params
            'grant_type=password&username=foo&username=bar&password=baz'
            # missing username
            'grant_type=password&password=baz'
            # missing password
            'grant_type=password&username=foo'
        ]
        self.validator.authenticate_client.side_effect = self.set_client
        for body in invalid_bodies:
            _, _, body, _ = self.legacy.create_token_response(token_uri,
                    body=body)
            self.assertEqual('invalid_request', json.loads(body)['error'])

        # Client credentials grant
        invalid_bodies = [
            # duplicate params
            'grant_type=client_credentials&scope=foo&scope=bar'
        ]
        for body in invalid_bodies:
            _, _, body, _ = self.backend.create_token_response(token_uri,
                    body=body)
            self.assertEqual('invalid_request', json.loads(body)['error'])

    def test_unauthorized_client(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        self.validator.validate_grant_type.return_value = False
        self.validator.validate_response_type.return_value = False
        self.validator.authenticate_client.side_effect = self.set_client
        token_uri = 'https://i.b/token'

        # Authorization code grant
        self.assertRaises(errors.UnauthorizedClientError,
                self.web.validate_authorization_request,
                'https://i.b/auth?response_type=code&client_id=foo')
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('unauthorized_client', json.loads(body)['error'])

        # Implicit grant
        self.assertRaises(errors.UnauthorizedClientError,
                self.mobile.validate_authorization_request,
                'https://i.b/auth?response_type=token&client_id=foo')

        # Password credentials grant
        _, _, body, _ = self.legacy.create_token_response(token_uri,
                body='grant_type=password&username=foo&password=bar')
        self.assertEqual('unauthorized_client', json.loads(body)['error'])

        # Client credentials grant
        _, _, body, _ = self.backend.create_token_response(token_uri,
                body='grant_type=client_credentials')
        self.assertEqual('unauthorized_client', json.loads(body)['error'])

    def test_access_denied(self):
        self.validator.authenticate_client.side_effect = self.set_client
        self.validator.confirm_redirect_uri.return_value = False
        token_uri = 'https://i.b/token'
        # Authorization code grant
        _, _, body, _ = self.web.create_token_response(token_uri,
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('access_denied', json.loads(body)['error'])

    def test_unsupported_response_type(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'

        # Authorization code grant
        self.assertRaises(errors.UnsupportedResponseTypeError,
                self.web.validate_authorization_request,
                'https://i.b/auth?response_type=foo&client_id=foo')

        # Implicit grant
        self.assertRaises(errors.UnsupportedResponseTypeError,
                self.mobile.validate_authorization_request,
                'https://i.b/auth?response_type=foo&client_id=foo')

    def test_invalid_scope(self):
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        self.validator.validate_scopes.return_value = False
        self.validator.authenticate_client.side_effect = self.set_client

        # Authorization code grant
        self.assertRaises(errors.InvalidScopeError,
                self.web.validate_authorization_request,
                'https://i.b/auth?response_type=code&client_id=foo')

        # Implicit grant
        self.assertRaises(errors.InvalidScopeError,
                self.mobile.validate_authorization_request,
                'https://i.b/auth?response_type=token&client_id=foo')

        # Password credentials grant
        _, _, body, _ = self.legacy.create_token_response(
                'https://i.b/token',
                body='grant_type=password&username=foo&password=bar')
        self.assertEqual('invalid_scope', json.loads(body)['error'])

        # Client credentials grant
        _, _, body, _ = self.backend.create_token_response(
                'https://i.b/token',
                body='grant_type=client_credentials')
        self.assertEqual('invalid_scope', json.loads(body)['error'])

    def test_server_error(self):
        def raise_error(*args, **kwargs):
            raise ValueError()

        self.validator.validate_client_id.side_effect = raise_error
        self.validator.authenticate_client.side_effect = raise_error
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'

        # Authorization code grant
        self.web.catch_errors = True
        _, _, _, s = self.web.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=code',
                scopes=['foo'])
        self.assertEqual(s, 500)
        _, _, _, s = self.web.create_token_response(
                'https://i.b/token',
                body='grant_type=authorization_code&code=foo',
                scopes=['foo'])
        self.assertEqual(s, 500)

        # Implicit grant
        self.mobile.catch_errors = True
        _, _, _, s = self.mobile.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=token',
                scopes=['foo'])
        self.assertEqual(s, 500)

        # Password credentials grant
        self.legacy.catch_errors = True
        _, _, _, s = self.legacy.create_token_response(
                'https://i.b/token',
                body='grant_type=password&username=foo&password=foo')
        self.assertEqual(s, 500)

        # Client credentials grant
        self.backend.catch_errors = True
        _, _, _, s = self.backend.create_token_response(
                'https://i.b/token',
                body='grant_type=client_credentials')
        self.assertEqual(s, 500)

    def test_temporarily_unavailable(self):
        # Authorization code grant
        self.web.available = False
        _, _, _, s = self.web.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=code',
                scopes=['foo'])
        self.assertEqual(s, 503)
        _, _, _, s = self.web.create_token_response(
                'https://i.b/token',
                body='grant_type=authorization_code&code=foo',
                scopes=['foo'])
        self.assertEqual(s, 503)

        # Implicit grant
        self.mobile.available = False
        _, _, _, s = self.mobile.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=token',
                scopes=['foo'])
        self.assertEqual(s, 503)

        # Password credentials grant
        self.legacy.available = False
        _, _, _, s = self.legacy.create_token_response(
                'https://i.b/token',
                body='grant_type=password&username=foo&password=foo')
        self.assertEqual(s, 503)

        # Client credentials grant
        self.backend.available = False
        _, _, _, s = self.backend.create_token_response(
                'https://i.b/token',
                body='grant_type=client_credentials')
        self.assertEqual(s, 503)

    def test_invalid_client(self):
        self.validator.authenticate_client.return_value = False
        self.validator.authenticate_client_id.return_value = False

        # Authorization code grant
        _, _, body, _ = self.web.create_token_response('https://i.b/token',
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('invalid_client', json.loads(body)['error'])

        # Password credentials grant
        _, _, body, _ = self.legacy.create_token_response('https://i.b/token',
                body='grant_type=password&username=foo&password=bar')
        self.assertEqual('invalid_client', json.loads(body)['error'])

        # Client credentials grant
        _, _, body, _ = self.legacy.create_token_response('https://i.b/token',
                body='grant_type=client_credentials')
        self.assertEqual('invalid_client', json.loads(body)['error'])

    def test_invalid_grant(self):
        self.validator.authenticate_client.side_effect = self.set_client

        # Authorization code grant
        self.validator.validate_code.return_value = False
        _, _, body, _ = self.web.create_token_response('https://i.b/token',
                body='grant_type=authorization_code&code=foo')
        self.assertEqual('invalid_grant', json.loads(body)['error'])

        # Password credentials grant
        self.validator.validate_user.return_value = False
        _, _, body, _ = self.legacy.create_token_response('https://i.b/token',
                body='grant_type=password&username=foo&password=bar')
        self.assertEqual('invalid_grant', json.loads(body)['error'])

    def test_unsupported_grant_type(self):
        self.validator.authenticate_client.side_effect = self.set_client

        # Authorization code grant
        _, _, body, _ = self.web.create_token_response('https://i.b/token',
                body='grant_type=bar&code=foo')
        self.assertEqual('unsupported_grant_type', json.loads(body)['error'])

        # Password credentials grant
        _, _, body, _ = self.legacy.create_token_response('https://i.b/token',
                body='grant_type=bar&username=foo&password=bar')
        self.assertEqual('unsupported_grant_type', json.loads(body)['error'])

        # Client credentials grant
        _, _, body, _ = self.backend.create_token_response('https://i.b/token',
                body='grant_type=bar')
        self.assertEqual('unsupported_grant_type', json.loads(body)['error'])


class ExtraCredentialsTest(TestCase):

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        self.web = WebApplicationServer(self.validator)
        self.mobile = MobileApplicationServer(self.validator)
        self.legacy = LegacyApplicationServer(self.validator)
        self.backend = BackendApplicationServer(self.validator)

    def test_post_authorization_request(self):
        def save_code(client_id, token, request):
            self.assertEqual('creds', request.extra)

        def save_token(token, request):
            self.assertEqual('creds', request.extra)

        # Authorization code grant
        self.validator.save_authorization_code.side_effect = save_code
        self.web.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=code',
                scopes=['foo'],
                credentials={'extra': 'creds'})

        # Implicit grant
        self.validator.save_bearer_token.side_effect = save_token
        self.web.create_authorization_response(
                'https://i.b/auth?client_id=foo&response_type=token',
                scopes=['foo'],
                credentials={'extra': 'creds'})

    def test_token_request(self):
        def save_token(token, request):
            self.assertIn('extra', token)

        self.validator.save_bearer_token.side_effect = save_token
        self.validator.authenticate_client.side_effect = self.set_client

        # Authorization code grant
        self.web.create_token_response('https://i.b/token',
                body='grant_type=authorization_code&code=foo',
                credentials={'extra': 'creds'})

        # Password credentials grant
        self.legacy.create_token_response('https://i.b/token',
                body='grant_type=password&username=foo&password=bar',
                credentials={'extra': 'creds'})

        # Client credentials grant
        self.backend.create_token_response('https://i.b/token',
                body='grant_type=client_credentials',
                credentials={'extra': 'creds'})
