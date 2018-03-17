# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
from oauthlib.openid.connect.core.grant_types.hybrid import HybridGrant

from ....oauth2.rfc6749.grant_types.test_authorization_code import AuthorizationCodeGrantTest


class OpenIDHybridInterferenceTest(AuthorizationCodeGrantTest):
    """Test that OpenID don't interfere with normal OAuth 2 flows."""

    def setUp(self):
        super(OpenIDHybridInterferenceTest, self).setUp()
        self.auth = HybridGrant(request_validator=self.mock_validator)
