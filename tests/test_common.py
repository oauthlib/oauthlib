# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

import sys

from oauthlib.common import (CaseInsensitiveDict, Request, add_params_to_uri,
                             extract_params, generate_client_id,
                             generate_nonce, generate_timestamp,
                             generate_token, unicode_type, urldecode)

from .unittest import TestCase

PARAMS_DICT = {'foo': 'bar', 'baz': '123', }
PARAMS_TWOTUPLE = [('foo', 'bar'), ('baz', '123')]
PARAMS_FORMENCODED = 'foo=bar&baz=123'
URI = 'http://www.someuri.com'


class EncodingTest(TestCase):

    def test_urldecode(self):
        self.assertItemsEqual(urldecode(''), [])
        self.assertItemsEqual(urldecode('='), [('', '')])
        self.assertItemsEqual(urldecode('%20'), [(' ', '')])
        self.assertItemsEqual(urldecode('+'), [(' ', '')])
        self.assertItemsEqual(urldecode('c2'), [('c2', '')])
        self.assertItemsEqual(urldecode('c2='), [('c2', '')])
        self.assertItemsEqual(urldecode('foo=bar'), [('foo', 'bar')])
        self.assertItemsEqual(urldecode('foo_%20~=.bar-'),
                              [('foo_ ~', '.bar-')])
        self.assertItemsEqual(urldecode('foo=1,2,3'), [('foo', '1,2,3')])
        self.assertItemsEqual(urldecode('foo=(1,2,3)'), [('foo', '(1,2,3)')])
        self.assertItemsEqual(urldecode('foo=bar.*'), [('foo', 'bar.*')])
        self.assertItemsEqual(urldecode('foo=bar@spam'), [('foo', 'bar@spam')])
        self.assertItemsEqual(urldecode('foo=bar/baz'), [('foo', 'bar/baz')])
        self.assertItemsEqual(urldecode('foo=bar?baz'), [('foo', 'bar?baz')])
        self.assertItemsEqual(urldecode('foo=bar\'s'), [('foo', 'bar\'s')])
        self.assertItemsEqual(urldecode('foo=$'), [('foo', '$')])
        self.assertRaises(ValueError, urldecode, 'foo bar')
        self.assertRaises(ValueError, urldecode, '%R')
        self.assertRaises(ValueError, urldecode, '%RA')
        self.assertRaises(ValueError, urldecode, '%AR')
        self.assertRaises(ValueError, urldecode, '%RR')


class ParameterTest(TestCase):

    def test_extract_params_dict(self):
        self.assertItemsEqual(extract_params(PARAMS_DICT), PARAMS_TWOTUPLE)

    def test_extract_params_twotuple(self):
        self.assertItemsEqual(extract_params(PARAMS_TWOTUPLE), PARAMS_TWOTUPLE)

    def test_extract_params_formencoded(self):
        self.assertItemsEqual(extract_params(PARAMS_FORMENCODED),
                              PARAMS_TWOTUPLE)

    def test_extract_params_blank_string(self):
        self.assertItemsEqual(extract_params(''), [])

    def test_extract_params_empty_list(self):
        self.assertItemsEqual(extract_params([]), [])

    def test_extract_non_formencoded_string(self):
        self.assertEqual(extract_params('not a formencoded string'), None)

    def test_extract_invalid(self):
        self.assertEqual(extract_params(object()), None)
        self.assertEqual(extract_params([('')]), None)

    def test_add_params_to_uri(self):
        correct = '%s?%s' % (URI, PARAMS_FORMENCODED)
        self.assertURLEqual(add_params_to_uri(URI, PARAMS_DICT), correct)
        self.assertURLEqual(add_params_to_uri(URI, PARAMS_TWOTUPLE), correct)


class GeneratorTest(TestCase):

    def test_generate_timestamp(self):
        timestamp = generate_timestamp()
        self.assertIsInstance(timestamp, unicode_type)
        self.assertTrue(int(timestamp))
        self.assertGreater(int(timestamp), 1331672335)

    def test_generate_nonce(self):
        """Ping me (ib-lundgren) when you discover how to test randomness."""
        nonce = generate_nonce()
        for i in range(50):
            self.assertNotEqual(nonce, generate_nonce())

    def test_generate_token(self):
        token = generate_token()
        self.assertEqual(len(token), 30)

        token = generate_token(length=44)
        self.assertEqual(len(token), 44)

        token = generate_token(length=6, chars="python")
        self.assertEqual(len(token), 6)
        for c in token:
            self.assertIn(c, "python")

    def test_generate_client_id(self):
        client_id = generate_client_id()
        self.assertEqual(len(client_id), 30)

        client_id = generate_client_id(length=44)
        self.assertEqual(len(client_id), 44)

        client_id = generate_client_id(length=6, chars="python")
        self.assertEqual(len(client_id), 6)
        for c in client_id:
            self.assertIn(c, "python")


class RequestTest(TestCase):

    def test_non_unicode_params(self):
        r = Request(
            b'http://a.b/path?query',
            http_method=b'GET',
            body=b'you=shall+pass',
            headers={
                b'a': b'b',
            }
        )
        self.assertEqual(r.uri, 'http://a.b/path?query')
        self.assertEqual(r.http_method, 'GET')
        self.assertEqual(r.body, 'you=shall+pass')
        self.assertEqual(r.decoded_body, [('you', 'shall pass')])
        self.assertEqual(r.headers, {'a': 'b'})

    def test_none_body(self):
        r = Request(URI)
        self.assertEqual(r.decoded_body, None)

    def test_empty_list_body(self):
        r = Request(URI, body=[])
        self.assertEqual(r.decoded_body, [])

    def test_empty_dict_body(self):
        r = Request(URI, body={})
        self.assertEqual(r.decoded_body, [])

    def test_empty_string_body(self):
        r = Request(URI, body='')
        self.assertEqual(r.decoded_body, [])

    def test_non_formencoded_string_body(self):
        body = 'foo bar'
        r = Request(URI, body=body)
        self.assertEqual(r.decoded_body, None)

    def test_param_free_sequence_body(self):
        body = [1, 1, 2, 3, 5, 8, 13]
        r = Request(URI, body=body)
        self.assertEqual(r.decoded_body, None)

    def test_list_body(self):
        r = Request(URI, body=PARAMS_TWOTUPLE)
        self.assertItemsEqual(r.decoded_body, PARAMS_TWOTUPLE)

    def test_dict_body(self):
        r = Request(URI, body=PARAMS_DICT)
        self.assertItemsEqual(r.decoded_body, PARAMS_TWOTUPLE)

    def test_getattr_existing_attribute(self):
        r = Request(URI, body='foo bar')
        self.assertEqual('foo bar', getattr(r, 'body'))

    def test_getattr_return_default(self):
        r = Request(URI, body='')
        actual_value = getattr(r, 'does_not_exist', 'foo bar')
        self.assertEqual('foo bar', actual_value)

    def test_getattr_raise_attribute_error(self):
        r = Request(URI, body='foo bar')
        with self.assertRaises(AttributeError):
            getattr(r, 'does_not_exist')

    def test_sanitizing_authorization_header(self):
        r = Request(URI, headers={'Accept': 'application/json',
                                  'Authorization': 'Basic Zm9vOmJhcg=='}
                    )
        self.assertNotIn('Zm9vOmJhcg==', repr(r))
        self.assertIn('<SANITIZED>', repr(r))
        # Double-check we didn't modify the underlying object:
        self.assertEqual(r.headers['Authorization'], 'Basic Zm9vOmJhcg==')

    def test_token_body(self):
        payload = 'client_id=foo&refresh_token=bar'
        r = Request(URI, body=payload)
        self.assertNotIn('bar', repr(r))
        self.assertIn('<SANITIZED>', repr(r))

        payload = 'refresh_token=bar&client_id=foo'
        r = Request(URI, body=payload)
        self.assertNotIn('bar', repr(r))
        self.assertIn('<SANITIZED>', repr(r))

    def test_password_body(self):
        payload = 'username=foo&password=bar'
        r = Request(URI, body=payload)
        self.assertNotIn('bar', repr(r))
        self.assertIn('<SANITIZED>', repr(r))

        payload = 'password=bar&username=foo'
        r = Request(URI, body=payload)
        self.assertNotIn('bar', repr(r))
        self.assertIn('<SANITIZED>', repr(r))

    def test_headers_params(self):
        r = Request(URI, headers={'token': 'foobar'}, body='token=banana')
        self.assertEqual(r.headers['token'], 'foobar')
        self.assertEqual(r.token, 'banana')


class CaseInsensitiveDictTest(TestCase):

    def test_basic(self):
        cid = CaseInsensitiveDict({})
        cid['a'] = 'b'
        cid['c'] = 'd'
        del cid['c']
        self.assertEqual(cid['A'], 'b')
        self.assertEqual(cid['a'], 'b')

    def test_update(self):
        cid = CaseInsensitiveDict({})
        cid.update({'KeY': 'value'})
        self.assertEqual(cid['kEy'], 'value')
