# -*- coding: utf-8 -*-
import oauthlib

from oauthlib.uri_validate import is_absolute_uri
import re

from tests.unittest import TestCase


class UriValidateTest(TestCase):

    def test_is_absolute_uri(self):

        self.assertIsInstance(is_absolute_uri('schema://example.com/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('https://example.com/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('https://example.com'), re.Match)
        self.assertIsInstance(is_absolute_uri('https://example.com:443/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('https://example.com:443/'), re.Match)
        self.assertIsInstance(is_absolute_uri('https://example.com:443'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://example.com'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://example.com/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://example.com:80/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('com.example.bundle.id:/'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://[::1]:38432/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://[::1]/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://[fd01:0001::1]/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://[fd01:1::1]/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://[0123:4567:89ab:cdef:0123:4567:89ab:cdef]/path'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://127.0.0.1:38432/'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://127.0.0.1:38432/'), re.Match)
        self.assertIsInstance(is_absolute_uri('http://127.1:38432/'), re.Match)

        self.assertIsNone(is_absolute_uri('http://example.com:notaport/path'))
        self.assertIsNone(is_absolute_uri('wrong'))
        self.assertIsNone(is_absolute_uri('http://[:1]:38432/path'))
        self.assertIsNone(is_absolute_uri('http://[abcd:efgh::1]/'), re.Match)
