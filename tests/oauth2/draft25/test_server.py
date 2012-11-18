# -*- coding: utf-8 -*-
from __future__ import absolute_import
from ...unittest import TestCase
import mock

from oauthlib.oauth2.draft25 import AuthorizationEndpoint, TokenEndpoint
from oauthlib.oauth2.draft25 import ResourceEndpoint
from oauthlib.oauth2.draft25.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.draft25.grant_types import ImplicitGrant
from oauthlib.oauth2.draft25.grant_types import ResourceOwnerPasswordCredentialsGrant
from oauthlib.oauth2.draft25.grant_types import ClientCredentialsGrant


class AuthorizationEndpointTest(TestCase):

    def setUp(self):
        mock_validator = mock.MagicMock()
        auth_code = AuthorizationCodeGrant(request_validator=mock_validator)
        implicit = ImplicitGrant(request_validator=mock_validator)
        response_types = {
                'code': auth_code,
                'token': implicit,
        }
        self.endpoint = AuthorizationEndpoint(response_types=response_types)

    def test_authorization_grant(self):
        pass

    def test_implicit_grant(self):
        pass

    def test_missing_type(self):
        pass

    def test_invalid_type(self):
        pass


class TokenEndpointTest(TestCase):

    def setUp(self):
        mock_validator = mock.MagicMock()
        auth_code = AuthorizationCodeGrant(request_validator=mock_validator)
        password = ResourceOwnerPasswordCredentialsGrant(request_validator=mock_validator)
        client = ClientCredentialsGrant(request_validator=mock_validator)
        grant_types = {
                'authorization_code': auth_code,
                'password': password,
                'client_credentials': client,
        }
        self.endpoint = TokenEndpoint(grant_types=grant_types)

    def test_authorization_grant(self):
        pass

    def test_password_grant(self):
        pass

    def test_client_grant(self):
        pass

    def test_missing_type(self):
        pass

    def test_invalid_type(self):
        pass


class ResourceEndpointTest(TestCase):

    def setUp(self):
        self.endpoint = ResourceEndpoint()

    def test_token_validation(self):
        pass

    def test_token_estimation(self):
        pass
