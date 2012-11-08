import sys
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

try:
    # check the system path first
    from unittest2 import *
except ImportError:
    if sys.version_info >= (2, 7):
        # unittest2 features are native in Python 2.7
        from unittest import *
    else:
        raise

# Python 3.1 does not provide assertIsInstance
if sys.version_info[1] == 1:
    TestCase.assertIsInstance = lambda self, obj, cls: self.assertTrue(isinstance(obj, cls))

# Python 3 does not provide assertItemsEqual
# TODO (ib-lundgren): Find out why and what their recommended alternative is
if sys.version_info[0] == 3:
    TestCase.assertItemsEqual = lambda self, a, b: self.assertEqual(sorted(a), sorted(b))


# URL comparison where query param order is insignifcant
def url_equals(self, a, b):
    parsed_a = urlparse.urlparse(a)
    parsed_b = urlparse.urlparse(b)
    query_a = urlparse.parse_qsl(a)
    query_b = urlparse.parse_qsl(b)
    self.assertEqual(parsed_a.scheme, parsed_b.scheme)
    self.assertEqual(parsed_a.netloc, parsed_b.netloc)
    self.assertEqual(parsed_a.path, parsed_b.path)
    self.assertEqual(parsed_a.params, parsed_b.params)
    self.assertEqual(parsed_a.fragment, parsed_b.fragment)
    self.assertEqual(parsed_a.username, parsed_b.username)
    self.assertEqual(parsed_a.password, parsed_b.password)
    self.assertEqual(parsed_a.hostname, parsed_b.hostname)
    self.assertEqual(parsed_a.port, parsed_b.port)
    self.assertItemsEqual(query_a, query_b)

TestCase.assertURLEqual = url_equals

# Form body comparison where order is insignificant
TestCase.assertFormBodyEqual = lambda self, a, b: self.assertItemsEqual(
        urlparse.parse_qsl(a), urlparse.parse_qsl(b))
