from __future__ import unicode_literals, absolute_import

from mock import MagicMock
from ....unittest import TestCase

from oauthlib.oauth1 import RequestValidator
from oauthlib.oauth1.rfc5849 import errors
from oauthlib.oauth1.rfc5849.endpoints import AuthorizationEndpoint


class ResourceEndpointTest(TestCase):

    def setUp(self):
        self.validator = MagicMock(wraps=RequestValidator())
        self.validator.verify_request_token.return_value = True
        self.validator.verify_realms.return_value = True
        self.validator.get_realms.return_value = ['test']
        self.validator.get_redirect_uri.return_value = 'https://c.b/cb'
        self.validator.save_verifier = MagicMock()
        self.endpoint = AuthorizationEndpoint(self.validator)
        self.uri = 'https://i.b/authorize?oauth_token=foo'

    def test_get_realms_and_credentials(self):
        realms, credentials = self.endpoint.get_realms_and_credentials(self.uri)
        self.assertEqual(realms, ['test'])

    def test_verify_token(self):
        self.validator.verify_request_token.return_value = False
        self.assertRaises(errors.InvalidClientError,
                self.endpoint.get_realms_and_credentials, self.uri)
        self.assertRaises(errors.InvalidClientError,
                self.endpoint.create_authorization_response, self.uri)

    def test_verify_realms(self):
        self.validator.verify_realms.return_value = False
        self.assertRaises(errors.InvalidRequestError,
                self.endpoint.create_authorization_response,
                self.uri,
                realms=['bar'])

    def test_create_authorization_response(self):
        u, h, b, s = self.endpoint.create_authorization_response(self.uri)
        self.assertEqual(s, 302)
        self.assertTrue(u.startswith('https://c.b/cb'))
        self.assertIn('oauth_verifier', u)
