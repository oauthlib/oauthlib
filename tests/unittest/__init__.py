import collections
import sys
from unittest import TestCase
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


# Somewhat consistent itemsequal between all python versions
if sys.version_info[0] == 3:
    TestCase.assertItemsEqual = TestCase.assertCountEqual


# URL comparison where query param order is insignifcant
def url_equals(self, a, b, parse_fragment=False):
    parsed_a = urlparse.urlparse(a, allow_fragments=parse_fragment)
    parsed_b = urlparse.urlparse(b, allow_fragments=parse_fragment)
    query_a = urlparse.parse_qsl(parsed_a.query)
    query_b = urlparse.parse_qsl(parsed_b.query)
    if parse_fragment:
        fragment_a = urlparse.parse_qsl(parsed_a.fragment)
        fragment_b = urlparse.parse_qsl(parsed_b.fragment)
        self.assertItemsEqual(fragment_a, fragment_b)
    else:
        self.assertEqual(parsed_a.fragment, parsed_b.fragment)
    self.assertEqual(parsed_a.scheme, parsed_b.scheme)
    self.assertEqual(parsed_a.netloc, parsed_b.netloc)
    self.assertEqual(parsed_a.path, parsed_b.path)
    self.assertEqual(parsed_a.params, parsed_b.params)
    self.assertEqual(parsed_a.username, parsed_b.username)
    self.assertEqual(parsed_a.password, parsed_b.password)
    self.assertEqual(parsed_a.hostname, parsed_b.hostname)
    self.assertEqual(parsed_a.port, parsed_b.port)
    self.assertItemsEqual(query_a, query_b)

TestCase.assertURLEqual = url_equals

# Form body comparison where order is insignificant
TestCase.assertFormBodyEqual = lambda self, a, b: self.assertItemsEqual(
        urlparse.parse_qsl(a), urlparse.parse_qsl(b))
