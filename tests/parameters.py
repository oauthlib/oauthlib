from __future__ import absolute_import

from .unittest import *

from oauthlib.parameters import *

class ParameterTests(TestCase):

    def test_order_oauth_parameters(self):
        unordered = {
            'oauth_foo': 'foo',
            'oauth_bar': 'bar',
            'lala': 123,
            'oauth_baz': 'baz', }
        expected = [
            ('oauth_bar', 'bar'),
            ('oauth_baz', 'baz'),
            ('oauth_foo', 'foo'),
            ('lala', 123)]
    self.assertEqual(order_oauth_parameters(params), expected)
