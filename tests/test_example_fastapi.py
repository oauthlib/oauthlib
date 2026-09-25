"""End-to-end test of examples/fastapi_async_sqlalchemy.py.

Skipped unless the optional example dependencies (examples/requirements.txt)
are installed; ``tox -e example`` runs it.
"""
import asyncio
import base64
import hashlib
import os
import tempfile
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

pytest.importorskip('fastapi')
pytest.importorskip('httpx')
pytest.importorskip('aiosqlite')
pytest.importorskip('sqlalchemy.ext.asyncio')
pytest.importorskip('python_multipart')

import httpx

from examples import fastapi_async_sqlalchemy as example
from tests.unittest import TestCase

REDIRECT = 'http://localhost:8080/callback'
SPA_REDIRECT = 'http://localhost:3000/callback'


class FastAPIExampleTest(TestCase):

    async def asyncSetUp(self):
        # A fresh file database per test: ':memory:' would share a single
        # connection (and therefore a single transaction) between sessions.
        self.tmp = tempfile.TemporaryDirectory()
        self.app = example.create_app(
            'sqlite+aiosqlite:///' + os.path.join(self.tmp.name, 'oauth.db'))
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url='https://auth.example')

    async def asyncTearDown(self):
        await self.http.aclose()
        await self.lifespan.__aexit__(None, None, None)
        self.tmp.cleanup()

    def _auth_query(self, client_id='demo-client', redirect_uri=REDIRECT, **extra):
        return urlencode(dict(response_type='code', client_id=client_id,
                              redirect_uri=redirect_uri, state='xyz', **extra))

    async def _code(self, query, scope='profile email'):
        r = await self.http.post('/authorize?' + query, data={'scope': scope},
                                 headers={'X-User': 'alice'})
        self.assertEqual(r.status_code, 302, r.text)
        params = parse_qs(urlparse(r.headers['location']).query)
        self.assertEqual(params['state'], ['xyz'])
        return params['code'][0]

    async def _token(self, data, basic=('demo-client', 'demo-secret')):
        headers = {}
        if basic:
            headers['Authorization'] = 'Basic ' + base64.b64encode(
                ('%s:%s' % basic).encode()).decode()
        return await self.http.post('/token', data=data, headers=headers)

    async def test_confidential_client_code_and_refresh_flow(self):
        r = await self.http.get('/authorize?' + self._auth_query(), headers={'X-User': 'alice'})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()['scopes'], ['profile'])

        code = await self._code(self._auth_query())
        r = await self._token({'grant_type': 'authorization_code', 'code': code,
                               'redirect_uri': REDIRECT})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()
        self.assertEqual(sorted(token['scope'].split()), ['email', 'profile'])

        me = await self.http.get('/me', headers={'Authorization': 'Bearer ' + token['access_token']})
        self.assertEqual(me.status_code, 200, me.text)
        self.assertEqual(me.json()['user'], 'alice')

        # Codes are single use.
        r = await self._token({'grant_type': 'authorization_code', 'code': code,
                               'redirect_uri': REDIRECT})
        self.assertEqual(r.json()['error'], 'invalid_grant')

        # Wrong client secret.
        r = await self._token({'grant_type': 'refresh_token', 'refresh_token': token['refresh_token']},
                              basic=('demo-client', 'nope'))
        self.assertEqual(r.json()['error'], 'invalid_client')

        # Refresh rotates the token pair.
        r = await self._token({'grant_type': 'refresh_token', 'refresh_token': token['refresh_token']})
        self.assertEqual(r.status_code, 200, r.text)
        new = r.json()
        self.assertNotEqual(new['access_token'], token['access_token'])
        old = await self.http.get('/me', headers={'Authorization': 'Bearer ' + token['access_token']})
        self.assertEqual(old.status_code, 401)
        ok = await self.http.get('/me', headers={'Authorization': 'Bearer ' + new['access_token']})
        self.assertEqual(ok.status_code, 200)

    async def test_public_client_requires_pkce(self):
        query = self._auth_query('demo-spa', SPA_REDIRECT)
        r = await self.http.post('/authorize?' + query, data={'scope': 'profile'},
                                 headers={'X-User': 'bob'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(parse_qs(urlparse(r.headers['location']).query)['error'], ['invalid_request'])

        verifier = 'v' * 64
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        code = await self._code(self._auth_query(
            'demo-spa', SPA_REDIRECT, code_challenge=challenge, code_challenge_method='S256'),
            scope='profile')

        base = {'grant_type': 'authorization_code', 'code': code,
                'redirect_uri': SPA_REDIRECT, 'client_id': 'demo-spa'}
        r = await self._token(dict(base, code_verifier='w' * 64), basic=None)
        self.assertEqual(r.json()['error'], 'invalid_grant')
        r = await self._token(dict(base, code_verifier=verifier), basic=None)
        self.assertEqual(r.status_code, 200, r.text)

    async def test_unknown_client_is_not_redirected(self):
        r = await self.http.get('/authorize?' + self._auth_query('nobody'), headers={'X-User': 'alice'})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn('location', r.headers)

    async def test_code_cannot_be_redeemed_twice_concurrently(self):
        code = await self._code(self._auth_query())
        data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT}
        results = await asyncio.gather(*(self._token(data) for _ in range(5)))
        statuses = sorted(r.status_code for r in results)
        self.assertEqual(statuses, [200, 400, 400, 400, 400], [r.text for r in results])
        self.assertEqual({r.json()['error'] for r in results if r.status_code == 400}, {'invalid_grant'})

    async def test_refresh_token_cannot_be_used_twice_concurrently(self):
        code = await self._code(self._auth_query())
        r = await self._token({'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT})
        data = {'grant_type': 'refresh_token', 'refresh_token': r.json()['refresh_token']}
        results = await asyncio.gather(*(self._token(data) for _ in range(5)))
        self.assertEqual(sorted(r.status_code for r in results), [200, 400, 400, 400, 400])

    async def test_failed_validation_does_not_burn_the_code(self):
        verifier = 'v' * 64
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        code = await self._code(self._auth_query(
            'demo-spa', SPA_REDIRECT, code_challenge=challenge, code_challenge_method='S256'),
            scope='profile')
        base = {'grant_type': 'authorization_code', 'code': code,
                'redirect_uri': SPA_REDIRECT, 'client_id': 'demo-spa'}
        r = await self._token(dict(base, redirect_uri='http://evil.example/cb', code_verifier=verifier), basic=None)
        self.assertEqual(r.status_code, 400)
        # The transaction that consumed the code was rolled back.
        r = await self._token(dict(base, code_verifier=verifier), basic=None)
        self.assertEqual(r.status_code, 200, r.text)

    async def test_non_ascii_client_secret_is_rejected_cleanly(self):
        r = await self._token({'grant_type': 'refresh_token', 'refresh_token': 'x'},
                              basic=('demo-client', 'sécret'))
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()['error'], 'invalid_client')
