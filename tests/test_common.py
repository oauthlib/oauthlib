# -*- coding: utf-8 -*-
import hashlib
import hmac
import logging
import os
import subprocess
import sys
import time
from unittest import mock

import oauthlib
from oauthlib.common import (
    CaseInsensitiveDict, Request, add_params_to_uri, extract_params,
    generate_client_id, generate_nonce, generate_timestamp, generate_token,
    log_safe, safe_string_equals, set_log_safe_key, urldecode,
)

from tests.unittest import TestCase

PARAMS_DICT = {'foo': 'bar', 'baz': '123', }
PARAMS_TWOTUPLE = [('foo', 'bar'), ('baz', '123')]
PARAMS_FORMENCODED = 'foo=bar&baz=123'
URI = 'http://www.someuri.com'


class EncodingTest(TestCase):

    def test_urldecode(self):
        self.assertCountEqual(urldecode(''), [])
        self.assertCountEqual(urldecode('='), [('', '')])
        self.assertCountEqual(urldecode('%20'), [(' ', '')])
        self.assertCountEqual(urldecode('+'), [(' ', '')])
        self.assertCountEqual(urldecode('c2'), [('c2', '')])
        self.assertCountEqual(urldecode('c2='), [('c2', '')])
        self.assertCountEqual(urldecode('foo=bar'), [('foo', 'bar')])
        self.assertCountEqual(urldecode('foo_%20~=.bar-'),
                              [('foo_ ~', '.bar-')])
        self.assertCountEqual(urldecode('foo=1,2,3'), [('foo', '1,2,3')])
        self.assertCountEqual(urldecode('foo=(1,2,3)'), [('foo', '(1,2,3)')])
        self.assertCountEqual(urldecode('foo=bar.*'), [('foo', 'bar.*')])
        self.assertCountEqual(urldecode('foo=bar@spam'), [('foo', 'bar@spam')])
        self.assertCountEqual(urldecode('foo=bar/baz'), [('foo', 'bar/baz')])
        self.assertCountEqual(urldecode('foo=bar?baz'), [('foo', 'bar?baz')])
        self.assertCountEqual(urldecode('foo=bar\'s'), [('foo', 'bar\'s')])
        self.assertCountEqual(urldecode('foo=$'), [('foo', '$')])
        self.assertRaises(ValueError, urldecode, 'foo bar')
        self.assertRaises(ValueError, urldecode, '%R')
        self.assertRaises(ValueError, urldecode, '%RA')
        self.assertRaises(ValueError, urldecode, '%AR')
        self.assertRaises(ValueError, urldecode, '%RR')


class ParameterTest(TestCase):

    def test_extract_params_dict(self):
        self.assertCountEqual(extract_params(PARAMS_DICT), PARAMS_TWOTUPLE)

    def test_extract_params_twotuple(self):
        self.assertCountEqual(extract_params(PARAMS_TWOTUPLE), PARAMS_TWOTUPLE)

    def test_extract_params_formencoded(self):
        self.assertCountEqual(extract_params(PARAMS_FORMENCODED),
                              PARAMS_TWOTUPLE)

    def test_extract_params_blank_string(self):
        self.assertCountEqual(extract_params(''), [])

    def test_extract_params_empty_list(self):
        self.assertCountEqual(extract_params([]), [])

    def test_extract_non_formencoded_string(self):
        self.assertIsNone(extract_params('not a formencoded string'))

    def test_extract_invalid(self):
        self.assertIsNone(extract_params(object()))
        self.assertIsNone(extract_params([('')]))

    def test_add_params_to_uri(self):
        correct = '{}?{}'.format(URI, PARAMS_FORMENCODED)
        self.assertURLEqual(add_params_to_uri(URI, PARAMS_DICT), correct)
        self.assertURLEqual(add_params_to_uri(URI, PARAMS_TWOTUPLE), correct)


class GeneratorTest(TestCase):

    def test_generate_timestamp(self):
        timestamp = generate_timestamp()
        self.assertIsInstance(timestamp, str)
        self.assertTrue(int(timestamp))
        self.assertGreater(int(timestamp), 1331672335)

    def test_generate_nonce(self):
        """Ping me (ib-lundgren) when you discover how to test randomness."""
        nonce = generate_nonce()
        for i in range(50):
            self.assertNotEqual(nonce, generate_nonce())

    def test_generate_nonce_entropy(self):
        """The nonce must draw at least 96 random bits from the CSPRNG.

        RFC 5849 section 3.3 requires the nonce to be unique across all
        requests sharing a timestamp, so the collision resistance within a
        single timestamp comes solely from the random component. Assert the
        random draw is at least 96 bits (up from the previous 64) so the
        birthday-bound collision probability stays negligible. See
        https://github.com/oauthlib/oauthlib/issues/946
        """
        with mock.patch('oauthlib.common.randbits') as mock_randbits:
            mock_randbits.return_value = 0
            generate_nonce()
        self.assertTrue(mock_randbits.called)
        requested_bits = mock_randbits.call_args[0][0]
        self.assertGreaterEqual(requested_bits, 96)

    def test_generate_nonce_length_within_default_limits(self):
        """The nonce must fit the default RequestValidator.nonce_length.

        The default OAuth1 validator accepts a nonce of 20 to 30 characters,
        so a generated nonce must land inside that window to remain valid
        against the library's own defaults.
        """
        for _ in range(200):
            self.assertLessEqual(len(generate_nonce()), 30)

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
        self.assertIsNone(r.decoded_body)

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
        self.assertIsNone(r.decoded_body)

    def test_param_free_sequence_body(self):
        body = [1, 1, 2, 3, 5, 8, 13]
        r = Request(URI, body=body)
        self.assertIsNone(r.decoded_body)

    def test_list_body(self):
        r = Request(URI, body=PARAMS_TWOTUPLE)
        self.assertCountEqual(r.decoded_body, PARAMS_TWOTUPLE)

    def test_dict_body(self):
        r = Request(URI, body=PARAMS_DICT)
        self.assertCountEqual(r.decoded_body, PARAMS_TWOTUPLE)

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

    def test_sanitizing_keeps_parameter_name(self):
        """Only the value is replaced; the parameter name is kept.

        ``_sanitize_body`` keeps the ``<name>=`` prefix in the redacted
        output, which keeps the repr readable for debugging.
        """
        r = Request(URI, body='client_id=foo&refresh_token=bar')
        self.assertIn('client_id=foo', repr(r))
        self.assertIn('refresh_token=<SANITIZED>', repr(r))

        r = Request(URI, body='username=foo&password=bar')
        self.assertIn('username=foo', repr(r))
        self.assertIn('password=<SANITIZED>', repr(r))
        self.assertNotIn('bar', repr(r))

    def test_sanitizing_emits_no_control_character(self):
        """The repr must stay printable, with no stray control characters."""
        r = Request(URI, body='client_id=foo&refresh_token=bar')
        self.assertNotIn('\x01', repr(r))

    def test_sanitizing_matches_regex_edge_cases(self):
        """Values containing '=' are fully redacted; empty values are kept."""
        r = Request(URI, body='token=abc==')
        self.assertNotIn('abc', repr(r))
        self.assertIn('token=<SANITIZED>', repr(r))

        r = Request(URI, body='token=')
        self.assertIn('token=', repr(r))

    def test_sanitizing_is_linear_time(self):
        """Adversarial bodies must not cause catastrophic backtracking."""
        for body in ('a' * 10000, 'a' * 10000 + '=', 'token' * 5000,
                     'a=b&' * 5000 + 'password=s'):
            Request(URI, body=body)  # warm up attributes
            request = Request(URI, body=body)
            start = time.monotonic()
            repr(request)
            self.assertLess(time.monotonic() - start, 1.0)

    def test_headers_params(self):
        r = Request(URI, headers={'token': 'foobar'}, body='token=banana')
        self.assertEqual(r.headers['token'], 'foobar')
        self.assertEqual(r.token, 'banana')

    def test_resource_param_from_body(self):
        """RFC 8707: resource parameter should be accessible via request.resource."""
        r = Request(URI, http_method='POST',
                    body='grant_type=authorization_code&resource=https%3A%2F%2Fapi.example.com')
        self.assertEqual(r.resource, 'https://api.example.com')

    def test_resource_param_from_query(self):
        """RFC 8707: resource parameter in query string should be accessible."""
        r = Request(URI + '?resource=https%3A%2F%2Fapi.example.com')
        self.assertEqual(r.resource, 'https://api.example.com')

    def test_resource_param_defaults_to_none(self):
        """RFC 8707: resource should be None when not provided."""
        r = Request(URI, body='grant_type=authorization_code')
        self.assertIsNone(r.resource)

    def test_sanitized_request_non_debug_mode(self):
        """make sure requests are sanitized when in non debug mode.
        For the debug mode, the other tests checking sanitization should prove
        that debug mode is working.
        """
        try:
            oauthlib.set_debug(False)
            r = Request(URI, headers={'token': 'foobar'}, body='token=banana')
            self.assertNotIn('token', repr(r))
            self.assertIn('SANITIZED', repr(r))
        finally:
            # set flag back for other tests
            oauthlib.set_debug(True)


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


class SafeStringEqualsTest(TestCase):

    def test_equal_strings(self):
        self.assertTrue(safe_string_equals('secret', 'secret'))

    def test_different_strings_same_length(self):
        self.assertFalse(safe_string_equals('secret', 'secrat'))

    def test_different_strings_different_length(self):
        self.assertFalse(safe_string_equals('secret', 'secrets'))

    def test_empty_strings(self):
        self.assertTrue(safe_string_equals('', ''))

    def test_bytes_operands(self):
        self.assertTrue(safe_string_equals(b'secret', b'secret'))
        self.assertFalse(safe_string_equals(b'secret', b'secrat'))

    def test_mixed_str_and_bytes_operands(self):
        self.assertTrue(safe_string_equals('secret', b'secret'))
        self.assertFalse(safe_string_equals('secret', b'secrat'))

    def test_unicode_operands(self):
        self.assertTrue(safe_string_equals(u'clé', u'clé'))
        self.assertFalse(safe_string_equals(u'clé', u'clo'))


class LogSafeTest(TestCase):

    def tearDown(self):
        set_log_safe_key(None)
        super().tearDown()

    def test_log_safe_stable_key_reproducible(self):
        set_log_safe_key(b'stable-test-key')
        self.assertEqual(log_safe('secret-token'),
                         'secr..' + hmac.new(b'stable-test-key', b'secret-token',
                                             hashlib.sha256).hexdigest()[:12])

    def test_log_safe_default_key_random(self):
        # default per-process key: same value yields the same fingerprint
        # within the process, but it is not a known/stable value
        self.assertEqual(log_safe('secret-token'), log_safe('secret-token'))
        self.assertNotEqual(log_safe('secret-token'), 'secr..' + hmac.new(
            b'stable-test-key', b'secret-token', hashlib.sha256).hexdigest()[:12])

    def test_log_safe_dict_and_none(self):
        set_log_safe_key(b'stable-test-key')
        sanitized = log_safe({'access_token': 'abcdefgh', 'refresh_token': None})
        self.assertEqual(sorted(sanitized), ['access_token', 'refresh_token'])
        self.assertIsNone(sanitized['refresh_token'])
        self.assertTrue(sanitized['access_token'].startswith('abcd..'))
        self.assertNotIn('abcdefgh', str(sanitized))

    def test_log_safe_no_secret_fragment(self):
        set_log_safe_key(b'stable-test-key')
        token = 's3cr3t-refresh-token-value'
        out = log_safe(token)
        self.assertTrue(out.startswith('s3cr..'))
        self.assertNotIn(token, out)
        self.assertNotIn(token[4:], out)

    def test_log_safe_eager_evaluation_with_debug_disabled(self):
        # log_safe is evaluated eagerly as a logging argument; it must not
        # raise even when the record is filtered out by the logger level
        set_log_safe_key('stable-test-key')  # str key, not bytes
        logger = logging.getLogger('oauthlib.test_log_safe')
        logger.setLevel(logging.CRITICAL)  # DEBUG disabled
        try:
            logger.debug('Validating refresh token %s.', log_safe('secret-token'))
        except TypeError:
            self.fail('log_safe raised TypeError with a str key and DEBUG disabled')

    def test_log_safe_env_key_regression(self):
        # Regression: OAUTHLIB_LOG_SAFE_KEY is a str from the environment and
        # must be usable by hmac.new without raising, even when the logging
        # call is filtered out (arguments are still evaluated eagerly).
        code = (
            "import logging\n"
            "logging.disable(logging.CRITICAL)\n"
            "from oauthlib.common import log_safe\n"
            "logger = logging.getLogger('oauthlib.regression')\n"
            "try:\n"
            "    logger.debug('Validating refresh token %s.', log_safe('secret-token'))\n"
            "except TypeError as e:\n"
            "    print('TYPEERROR: %s' % e)\n"
            "else:\n"
            "    print('OK')\n"
        )
        env = dict(os.environ, OAUTHLIB_LOG_SAFE_KEY='stable-test-key')
        result = subprocess.run(  # noqa: S603 - sys.executable is not untrusted input
            [sys.executable, '-c', code],
            env=env, capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), 'OK')
