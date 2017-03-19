from __future__ import absolute_import, unicode_literals
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import mock

from ....unittest import TestCase
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc6749.grant_types import OpenIDConnectAuthCode
from oauthlib.oauth2.rfc6749.endpoints.authorization import AuthorizationEndpoint

class OpenIDConnectEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = self.set_client
        grant = OpenIDConnectAuthCode(request_validator=self.mock_validator)
        bearer = BearerToken(self.mock_validator)
        self.endpoint = AuthorizationEndpoint(grant, bearer,
                                              response_types={'code': grant})
        params = {
            'prompt': 'consent',
            'state': 'abc',
            'redirect_uri': 'https://a.b/cb',
            'response_type': 'code',
            'client_id': 'abcdef',
            'scope': 'hello openid'
        }
        self.url = 'http://a.b/path?' + urlencode(params)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    @mock.patch('oauthlib.common.generate_token')
    def test_authorization_endpoint_handles_prompt(self, generate_token):
        generate_token.return_value = "MOCK_CODE"
        # In the GET view:
        scopes, creds = self.endpoint.validate_authorization_request(self.url)
        # In the POST view:
        creds['scopes'] = scopes
        h, b, s = self.endpoint.create_authorization_response(self.url,
                                                        credentials=creds)
        expected = 'https://a.b/cb?state=abc&code=MOCK_CODE'
        self.assertURLEqual(h['Location'], expected)
        self.assertEqual(b, None)
        self.assertEqual(s, 302)
