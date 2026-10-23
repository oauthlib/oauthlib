# -*- coding: utf-8 -*-
import os

from tests.unittest import TestCase

DOCS_ROOT = os.path.join(os.path.dirname(__file__), os.pardir, 'docs')


class PublicClientGrantGuidanceTest(TestCase):
    """Lock in current OAuth security guidance for public clients (#794)."""

    def _read(self, *parts):
        path = os.path.join(DOCS_ROOT, *parts)
        with open(path, encoding='utf-8') as f:
            return f.read()

    def test_comparison_page_recommends_auth_code_pkce(self):
        text = self._read('oauth_1_versus_oauth_2.rst')
        start = text.index('user controlled devices')
        end = text.index('Similar to above but without', start)
        section = text[start:end]
        self.assertIn(
            '**(Provider)** Offer :doc:`oauth2/grants/authcode`', section)
        self.assertIn('PKCE', section)
        self.assertNotIn(
            '**(Provider)** Offer :doc:`oauth2/grants/implicit`', section)
        self.assertIn('webapplicationclient', section.lower())
        self.assertNotIn('mobileapplicationclient', section.lower())

    def test_grant_types_overview_recommends_pkce_for_public_clients(self):
        text = ' '.join(self._read('oauth2', 'grants', 'grants.rst').split())
        self.assertIn('PKCE', text)
        self.assertIn('no longer recommended', text)

    def test_implicit_grant_page_warns_to_use_pkce(self):
        text = self._read('oauth2', 'grants', 'implicit.rst')
        self.assertIn('.. warning::', text)
        self.assertIn('PKCE', text)
        self.assertIn('authcode', text)
