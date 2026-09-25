from unittest import mock
from unittest.mock import MagicMock

from oauthlib.oauth1 import RequestValidator
from oauthlib.oauth1.rfc5849 import errors
from oauthlib.oauth1.rfc5849.endpoints import AuthorizationEndpoint

from tests.unittest import TestCase, oauth1_validator_mock


class AuthorizationEndpointTest(TestCase):

    def setUp(self):
        self.validator = oauth1_validator_mock(wraps=RequestValidator())
        self.validator.verify_request_token.return_value = True
        self.validator.verify_realms.return_value = True
        self.validator.get_realms.return_value = ['test']
        self.validator.save_verifier = mock.AsyncMock()
        self.endpoint = AuthorizationEndpoint(self.validator)
        self.uri = 'https://i.b/authorize?oauth_token=foo'

    async def test_get_realms_and_credentials(self):
        realms, _credentials = await self.endpoint.get_realms_and_credentials(self.uri)
        self.assertEqual(realms, ['test'])

    async def test_verify_token(self):
        self.validator.verify_request_token.return_value = False
        await self.assertRaisesAsync(errors.InvalidClientError,
                self.endpoint.get_realms_and_credentials, self.uri)
        await self.assertRaisesAsync(errors.InvalidClientError,
                self.endpoint.create_authorization_response, self.uri)

    async def test_verify_realms(self):
        self.validator.verify_realms.return_value = False
        await self.assertRaisesAsync(errors.InvalidRequestError,
                self.endpoint.create_authorization_response,
                self.uri,
                realms=['bar'])

    async def test_create_authorization_response(self):
        self.validator.get_redirect_uri.return_value = 'https://c.b/cb'
        h, _b, s = await self.endpoint.create_authorization_response(self.uri)
        self.assertEqual(s, 302)
        self.assertIn('Location', h)
        location = h['Location']
        self.assertTrue(location.startswith('https://c.b/cb'))
        self.assertIn('oauth_verifier', location)

    async def test_create_authorization_response_oob(self):
        self.validator.get_redirect_uri.return_value = 'oob'
        h, b, s = await self.endpoint.create_authorization_response(self.uri)
        self.assertEqual(s, 200)
        self.assertNotIn('Location', h)
        self.assertIn('oauth_verifier', b)
        self.assertIn('oauth_token', b)
