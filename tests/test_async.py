"""Tests for the async server-side contract.

These cover guarantees that only exist because the server side is async:
strict ``async def`` validator overrides, awaiting of sync-or-async user
hooks, the async error-handling decorator, and an end-to-end flow driven by a
real (non-mock) async validator, including concurrent requests.
"""
import asyncio
import functools
import json
from urllib.parse import parse_qs, urlparse

from oauthlib import oauth1
from oauthlib.aio import AsyncInterfaceMixin, maybe_await
from oauthlib.oauth2 import (
    BackendApplicationServer, RequestValidator, WebApplicationServer,
)
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.endpoints.base import (
    BaseEndpoint, catch_errors_and_unavailability,
)
from oauthlib.openid import RequestValidator as OIDCRequestValidator

from tests.unittest import TestCase


class MaybeAwaitTest(TestCase):

    async def test_plain_value(self):
        self.assertEqual(await maybe_await(42), 42)

    async def test_awaitable(self):
        async def f():
            return 42
        self.assertEqual(await maybe_await(f()), 42)


class StrictAsyncOverrideTest(TestCase):

    def test_sync_override_of_async_method_is_rejected(self):
        with self.assertRaisesRegex(TypeError, 'validate_client_id.*async def'):
            class Bad(RequestValidator):
                def validate_client_id(self, client_id, request, *args, **kwargs):
                    return True

    def test_sync_override_rejected_through_intermediate_class(self):
        class Middle(OIDCRequestValidator):
            pass

        with self.assertRaisesRegex(TypeError, 'get_userinfo_claims'):
            class Bad(Middle):
                def get_userinfo_claims(self, request):
                    return {}

    def test_async_override_is_accepted(self):
        class Good(RequestValidator):
            async def validate_client_id(self, client_id, request, *args, **kwargs):
                return True

            def helper(self):  # new sync methods are fine
                return 1

        self.assertEqual(Good().helper(), 1)

    def test_oauth1_sync_helpers_stay_sync(self):
        # check_* are pure syntax checks and properties are config: both stay sync.
        class V(oauth1.RequestValidator):
            def check_client_key(self, client_key):
                return True

            @property
            def enforce_ssl(self):
                return False

            async def validate_client_key(self, client_key, request):
                return True

        self.assertTrue(V().check_client_key('x'))

    def test_oauth1_sync_override_of_async_method_is_rejected(self):
        with self.assertRaises(TypeError):
            class Bad(oauth1.RequestValidator):
                def get_client_secret(self, client_key, request):
                    return 'secret'

    def test_sync_override_from_mixin_is_rejected(self):
        class DBMixin:
            def validate_client_id(self, client_id, request, *args, **kwargs):
                return True

        with self.assertRaisesRegex(TypeError, r'defined on \S*DBMixin\)'):
            class Bad(DBMixin, RequestValidator):
                pass

    def test_async_override_from_mixin_is_accepted(self):
        class DBMixin:
            async def validate_client_id(self, client_id, request, *args, **kwargs):
                return True

        class Good(DBMixin, RequestValidator):
            pass

        self.assertTrue(issubclass(Good, RequestValidator))

    def test_staticmethod_and_decorated_overrides(self):
        with self.assertRaises(TypeError):
            class BadStatic(RequestValidator):
                @staticmethod
                def validate_client_id(client_id, request, *args, **kwargs):
                    return True

        with self.assertRaises(TypeError):
            class BadCached(RequestValidator):
                @functools.lru_cache
                def validate_client_id(self, client_id, request, *args, **kwargs):
                    return True

        def logged(f):
            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                return await f(*args, **kwargs)
            return wrapper

        class GoodDecorated(RequestValidator):
            @staticmethod
            async def validate_client_id(client_id, request, *args, **kwargs):
                return True

            @logged
            async def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
                return True

        self.assertTrue(issubclass(GoodDecorated, RequestValidator))

    def test_mixin_only_checks_methods_async_in_a_base(self):
        class Base(AsyncInterfaceMixin):
            def sync_method(self):
                return 1

        class Child(Base):
            def sync_method(self):
                return 2

        self.assertEqual(Child().sync_method(), 2)


class CatchErrorsDecoratorTest(TestCase):

    def test_rejects_sync_function(self):
        with self.assertRaises(TypeError):
            @catch_errors_and_unavailability
            def sync(endpoint, uri):
                return {}, '', 200

    async def test_catches_errors_raised_while_awaiting(self):
        class E(BaseEndpoint):
            @catch_errors_and_unavailability
            async def boom(self, uri):
                await asyncio.sleep(0)
                raise ValueError('db down')

        e = E()
        e.catch_errors = True
        _, body, status = await e.boom('https://i.b/')
        self.assertEqual(status, 500)
        self.assertIn('server_error', body)

        e.catch_errors = False
        with self.assertRaises(ValueError):
            await e.boom('https://i.b/')


class InMemoryAsyncValidator(RequestValidator):
    """A real async validator; every method yields to the event loop."""

    def __init__(self):
        self.codes = {}
        self.tokens = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def _io(self):
        # Simulate a round trip to a database and record concurrency.
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        await asyncio.sleep(0.01)
        self.in_flight -= 1

    async def client_authentication_required(self, request, *args, **kwargs):
        return True

    async def authenticate_client(self, request, *args, **kwargs):
        await self._io()
        request.client = type('Client', (), {'client_id': 'abc'})()
        return True

    async def validate_client_id(self, client_id, request, *args, **kwargs):
        await self._io()
        return client_id == 'abc'

    async def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return redirect_uri == 'https://client.example/cb'

    async def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return 'https://client.example/cb'

    async def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return True

    async def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return set(scopes) <= {'read', 'write'}

    async def get_default_scopes(self, client_id, request, *args, **kwargs):
        return ['read']

    async def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        await self._io()
        self.codes[code['code']] = {'user': request.user, 'scopes': request.scopes}

    async def validate_code(self, client_id, code, client, request, *args, **kwargs):
        await self._io()
        data = self.codes.get(code)
        if data is None:
            return False
        request.user = data['user']
        request.scopes = data['scopes']
        return True

    async def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        return redirect_uri == 'https://client.example/cb'

    async def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return True

    async def save_bearer_token(self, token, request, *args, **kwargs):
        await self._io()
        self.tokens.append(token)

    async def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        await self._io()
        self.codes.pop(code, None)

    async def validate_bearer_token(self, token, scopes, request):
        await self._io()
        return any(t['access_token'] == token for t in self.tokens)


class EndToEndAsyncTest(TestCase):

    def setUp(self):
        self.validator = InMemoryAsyncValidator()
        self.server = WebApplicationServer(self.validator)

    async def _authorize(self):
        uri = ('https://server.example/authorize?response_type=code'
               '&client_id=abc&redirect_uri=https%3A%2F%2Fclient.example%2Fcb')
        scopes, _info = await self.server.validate_authorization_request(uri)
        self.assertEqual(scopes, ['read'])
        headers, _, status = await self.server.create_authorization_response(
            uri, scopes=scopes, credentials={'user': 'alice'})
        self.assertEqual(status, 302)
        return parse_qs(urlparse(headers['Location']).query)['code'][0]

    async def _exchange(self, code):
        body = ('grant_type=authorization_code&code=%s'
                '&redirect_uri=https%%3A%%2F%%2Fclient.example%%2Fcb' % code)
        return await self.server.create_token_response(
            'https://server.example/token', http_method='POST', body=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'})

    async def test_authorization_code_flow(self):
        code = await self._authorize()
        _, body, status = await self._exchange(code)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertEqual(token['token_type'], 'Bearer')

        # The code is single use.
        _, body, status = await self._exchange(code)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'invalid_grant')

        valid, _request = await self.server.verify_request(
            'https://server.example/api',
            headers={'Authorization': 'Bearer ' + token['access_token']},
            scopes=['read'])
        self.assertTrue(valid)

        valid, _ = await self.server.verify_request(
            'https://server.example/api',
            headers={'Authorization': 'Bearer nope'}, scopes=['read'])
        self.assertFalse(valid)

    async def test_requests_are_processed_concurrently(self):
        codes = [await self._authorize() for _ in range(5)]
        self.validator.max_in_flight = 0
        results = await asyncio.gather(*(self._exchange(c) for c in codes))
        self.assertEqual([r[2] for r in results], [200] * 5)
        # With a blocking (sync) validator this would stay at 1.
        self.assertGreater(self.validator.max_in_flight, 1)


class AsyncHooksTest(TestCase):

    def setUp(self):
        self.validator = InMemoryAsyncValidator()

    async def test_async_token_generator_and_expires_in(self):
        async def token_generator(request):
            await asyncio.sleep(0)
            return 'generated-token'

        async def expires_in(request):
            return 42

        server = BackendApplicationServer(
            self.validator, token_generator=token_generator, token_expires_in=expires_in)
        _, body, status = await server.create_token_response(
            'https://server.example/token', http_method='POST',
            body='grant_type=client_credentials',
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(status, 200, body)
        token = json.loads(body)
        self.assertEqual(token['access_token'], 'generated-token')
        self.assertEqual(token['expires_in'], 42)

    async def test_async_custom_validator_errors_propagate(self):
        async def reject(request):
            await asyncio.sleep(0)
            raise errors.AccessDeniedError(request=request)

        server = BackendApplicationServer(self.validator)
        server.grant_types['client_credentials'].custom_validators.pre_token.append(reject)
        _, body, status = await server.create_token_response(
            'https://server.example/token', http_method='POST',
            body='grant_type=client_credentials',
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(status, 400, body)
        self.assertEqual(json.loads(body)['error'], 'access_denied')

    async def test_sync_and_async_token_modifiers(self):
        def sync_modifier(token):
            token['sync'] = True
            return token

        async def async_modifier(token):
            await asyncio.sleep(0)
            token['async'] = True
            return token

        server = BackendApplicationServer(self.validator)
        grant = server.grant_types['client_credentials']
        grant.register_token_modifier(sync_modifier)
        grant.register_token_modifier(async_modifier)
        _, body, _ = await server.create_token_response(
            'https://server.example/token', http_method='POST',
            body='grant_type=client_credentials',
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
        token = json.loads(body)
        self.assertTrue(token['sync'])
        self.assertTrue(token['async'])
