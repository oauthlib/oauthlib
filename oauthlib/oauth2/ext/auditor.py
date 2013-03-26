# A functionality/security auditor that can be used to verify the correctness
# of a live OAuth 2 provider implementation given certain credentials.

# Implemented as a unittest class that you can subclass, configure and
# run against any spec compliant provider.

# Uses requests for HTTP requests, pip install requests
# Uses selenium to drive authorizations, pip install selenium

from __future__ import absolute_import

import requests
import selenium
import unittest


class OAuth1Auditor(unittest.TestCase):
    # Aiming for initial release in oauthlib 0.5
    pass


class OAuth2Auditor(unittest.TestCase):
    """Verify your OAuth 2 provider implementation live."""

    def setUp(self):
        self.grant_types = ['supported', 'grant types']
        self.response_types = ['supported', 'response types']
        self.clients = [('client id', ['grant types'], ['redirect uris'], ['scope', 'list'])]
        self.authorization_url = 'https://your.site/authorize'
        self.token_url = 'https://your.site/token'
        self.protected_resources = [('/url', ['scope', 'list'])]
        self.configure()

    def configure(self):
        """Configure the credentials that will be exercised by the auditor."""
        raise NotImplementedError('Subclasses must implement this method.')

    def authenticate_client(self, request):
        """Add authentication credentials to the request object."""
        raise NotImplementedError('Subclasses must implement this method.')

    def select_scopes(self, webdriver, scopes):
        """Select scopes in your authorization view using webdriver."""
        raise NotImplementedError('Subclasses must implement this method.')

    def test_authorization_code_grant_flow(self):
        """Auth + Token + Refresh flow."""
        pass

    def test_implicit_grant_flow(self):
        """Auth + Token flow. Ensure no refresh token."""
        pass

    def test_password_grant_flow(self):
        """Token + Refresh flow."""
        pass

    def test_client_credentials_grant_flow(self):
        """Token flow. Ensure no refresh token."""
        pass

    def test_authorization_code_reuse(self):
        """Ensure authorization codes are only valid once."""
        pass

    def test_unauthorized_scope_access(self):
        """Ensure protected views account for scope restrictions."""
        pass

    def test_unauthorized_scope_request(self):
        """Ensure clients can't request scope access outside their reach."""
        pass

    def test_scope_change_during_authorization(self):
        """Ensure users can opt-out of scopes."""
        pass

    def test_mismatching_redirect_uri(self):
        """Ensure only exact matches of redirect URIs are allowed."""
        pass

    def test_no_default_redirect_uri(self):
        """Ensure no random redirect uri is set when no default exists."""
        pass

    def test_state_preservation(self):
        """Ensure state remains unchanged throughout auth flow."""
        pass

    def test_token_request_redirect_uri_mismatch(self):
        """Ensure redirect_uri is equal in auth and token request."""
        pass

    def test_https(self):
        """OAuth 2 **requires** HTTPS everywhere."""
        pass

    def test_client_grant_types(self):
        """Ensure client can only use one grant type."""
        pass

    def test_client_response_types(self):
        """Ensure client can only use the response type matching its grant type."""
        pass

    def test_wrong_client_valid_code(self):
        """Ensure one client can't use the auth code of another."""
        pass
