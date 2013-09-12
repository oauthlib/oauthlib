from __future__ import absolute_import, unicode_literals

import datetime
import os

from ...unittest import TestCase
from oauthlib.oauth2.rfc6749.utils import escape, host_from_uri
from oauthlib.oauth2.rfc6749.utils import generate_age
from oauthlib.oauth2.rfc6749.utils import is_secure_transport
from oauthlib.oauth2.rfc6749.utils import params_from_uri


class UtilsTests(TestCase):

    def test_escape(self):
        """Assert that we are only escaping unicode"""
        self.assertRaises(ValueError, escape, b"I am a string type. Not a unicode type.")
        self.assertEqual(escape("I am a unicode type."), "I%20am%20a%20unicode%20type.")

    def test_host_from_uri(self):
        """Test if hosts and ports are properly extracted from URIs.

        This should be done according to the MAC Authentication spec.
        Defaults ports should be provided when none is present in the URI.
        """
        self.assertEqual(host_from_uri('http://a.b-c.com:8080'), ('a.b-c.com', '8080'))
        self.assertEqual(host_from_uri('https://a.b.com:8080'), ('a.b.com', '8080'))
        self.assertEqual(host_from_uri('http://www.example.com'), ('www.example.com', '80'))
        self.assertEqual(host_from_uri('https://www.example.com'), ('www.example.com', '443'))

    def test_is_secure_transport(self):
        """Test check secure uri."""
        if 'DEBUG' in os.environ:
            del os.environ['DEBUG']

        self.assertTrue(is_secure_transport('https://example.com'))
        self.assertFalse(is_secure_transport('http://example.com'))

        os.environ['DEBUG'] = '1'
        self.assertTrue(is_secure_transport('http://example.com'))
        del os.environ['DEBUG']

    def test_params_from_uri(self):
        self.assertEqual(params_from_uri('http://i.b/?foo=bar&g&scope=a+d'),
                         {'foo': 'bar', 'g': '', 'scope': ['a', 'd']})

    def test_generate_age(self):
        issue_time = datetime.datetime.now() - datetime.timedelta(
                days=3, minutes=1, seconds=4)
        self.assertGreater(float(generate_age(issue_time)), 259263.0)
