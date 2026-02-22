# -*- coding: utf-8 -*-
import oauthlib
from oauthlib.common import (
    CaseInsensitiveDict,
    Request,
    add_params_to_uri,
    extract_params,
    generate_client_id,
    generate_nonce,
    generate_timestamp,
    generate_token,
    urldecode,
)

from tests.unittest import TestCase
import pytest

PARAMS_DICT = {
    "foo": "bar",
    "baz": "123",
}
PARAMS_TWOTUPLE = [("foo", "bar"), ("baz", "123")]
PARAMS_FORMENCODED = "foo=bar&baz=123"
URI = "http://www.someuri.com"


def test_urldecode():
    case = TestCase()
    case.assertCountEqual(urldecode(""), [])
    case.assertCountEqual(urldecode("="), [("", "")])
    case.assertCountEqual(urldecode("%20"), [(" ", "")])
    case.assertCountEqual(urldecode("+"), [(" ", "")])
    case.assertCountEqual(urldecode("c2"), [("c2", "")])
    case.assertCountEqual(urldecode("c2="), [("c2", "")])
    case.assertCountEqual(urldecode("foo=bar"), [("foo", "bar")])
    case.assertCountEqual(urldecode("foo_%20~=.bar-"), [("foo_ ~", ".bar-")])
    case.assertCountEqual(urldecode("foo=1,2,3"), [("foo", "1,2,3")])
    case.assertCountEqual(urldecode("foo=(1,2,3)"), [("foo", "(1,2,3)")])
    case.assertCountEqual(urldecode("foo=bar.*"), [("foo", "bar.*")])
    case.assertCountEqual(urldecode("foo=bar@spam"), [("foo", "bar@spam")])
    case.assertCountEqual(urldecode("foo=bar/baz"), [("foo", "bar/baz")])
    case.assertCountEqual(urldecode("foo=bar?baz"), [("foo", "bar?baz")])
    case.assertCountEqual(urldecode("foo=bar's"), [("foo", "bar's")])
    case.assertCountEqual(urldecode("foo=$"), [("foo", "$")])
    with pytest.raises(ValueError, match="Error trying to decode a non urlencoded string.*"):
        urldecode("foo bar")
    with pytest.raises(ValueError, match="Invalid hex encoding in query string."):
        urldecode("%R")
    with pytest.raises(ValueError, match="Invalid hex encoding in query string."):
        urldecode("%RA")
    with pytest.raises(ValueError, match="Invalid hex encoding in query string."):
        urldecode("%AR")
    with pytest.raises(ValueError, match="Invalid hex encoding in query string."):
        urldecode("%RR")


def test_extract_params_dict():
    case = TestCase()
    case.assertCountEqual(extract_params(PARAMS_DICT), PARAMS_TWOTUPLE)


def test_extract_params_twotuple():
    case = TestCase()
    case.assertCountEqual(extract_params(PARAMS_TWOTUPLE), PARAMS_TWOTUPLE)


def test_extract_params_formencoded():
    case = TestCase()
    case.assertCountEqual(extract_params(PARAMS_FORMENCODED), PARAMS_TWOTUPLE)


def test_extract_params_blank_string():
    case = TestCase()
    case.assertCountEqual(extract_params(""), [])


def test_extract_params_empty_list():
    case = TestCase()
    case.assertCountEqual(extract_params([]), [])


def test_extract_non_formencoded_string():
    assert extract_params("not a formencoded string") is None


def test_extract_invalid():
    assert extract_params(object()) is None
    assert extract_params([("")]) is None


def test_add_params_to_uri():
    case = TestCase()
    correct = "{}?{}".format(URI, PARAMS_FORMENCODED)
    case.assertURLEqual(add_params_to_uri(URI, PARAMS_DICT), correct)
    case.assertURLEqual(add_params_to_uri(URI, PARAMS_TWOTUPLE), correct)


def test_generate_timestamp():
    timestamp = generate_timestamp()
    assert isinstance(timestamp, str)
    assert int(timestamp)
    assert int(timestamp) > 1331672335


def test_generate_nonce():
    """Ping me (ib-lundgren) when you discover how to test randomness."""
    nonce = generate_nonce()
    for i in range(50):
        assert nonce != generate_nonce()


def test_generate_token():
    token = generate_token()
    assert len(token) == 30
    token = generate_token(length=44)
    assert len(token) == 44
    token = generate_token(length=6, chars="python")
    assert len(token) == 6
    for c in token:
        assert c in "python"


def test_generate_client_id():
    client_id = generate_client_id()
    assert len(client_id) == 30
    client_id = generate_client_id(length=44)
    assert len(client_id) == 44
    client_id = generate_client_id(length=6, chars="python")
    assert len(client_id) == 6
    for c in client_id:
        assert c in "python"


def test_non_unicode_params():
    r = Request(
        b"http://a.b/path?query",
        http_method=b"GET",
        body=b"you=shall+pass",
        headers={
            b"a": b"b",
        },
    )
    assert r.uri == "http://a.b/path?query"
    assert r.http_method == "GET"
    assert r.body == "you=shall+pass"
    assert r.decoded_body == [("you", "shall pass")]
    assert r.headers == {"a": "b"}


def test_none_body():
    r = Request(URI)
    assert r.decoded_body is None


def test_empty_list_body():
    r = Request(URI, body=[])
    assert r.decoded_body == []


def test_empty_dict_body():
    r = Request(URI, body={})
    assert r.decoded_body == []


def test_empty_string_body():
    r = Request(URI, body="")
    assert r.decoded_body == []


def test_non_formencoded_string_body():
    body = "foo bar"
    r = Request(URI, body=body)
    assert r.decoded_body is None


def test_param_free_sequence_body():
    body = [1, 1, 2, 3, 5, 8, 13]
    r = Request(URI, body=body)
    assert r.decoded_body is None


def test_list_body():
    case = TestCase()
    r = Request(URI, body=PARAMS_TWOTUPLE)
    case.assertCountEqual(r.decoded_body, PARAMS_TWOTUPLE)


def test_dict_body():
    case = TestCase()
    r = Request(URI, body=PARAMS_DICT)
    case.assertCountEqual(r.decoded_body, PARAMS_TWOTUPLE)


def test_getattr_existing_attribute():
    r = Request(URI, body="foo bar")
    assert getattr(r, "body") == "foo bar"


def test_getattr_return_default():
    r = Request(URI, body="")
    actual_value = getattr(r, "does_not_exist", "foo bar")
    assert actual_value == "foo bar"


def test_getattr_raise_attribute_error():
    r = Request(URI, body="foo bar")
    with pytest.raises(AttributeError):
        getattr(r, "does_not_exist")


def test_sanitizing_authorization_header():
    r = Request(URI, headers={"Accept": "application/json", "Authorization": "Basic Zm9vOmJhcg=="})
    assert "Zm9vOmJhcg==" not in repr(r)
    assert "<SANITIZED>" in repr(r)
    assert r.headers["Authorization"] == "Basic Zm9vOmJhcg=="


def test_token_body():
    payload = "client_id=foo&refresh_token=bar"
    r = Request(URI, body=payload)
    assert "bar" not in repr(r)
    assert "<SANITIZED>" in repr(r)
    payload = "refresh_token=bar&client_id=foo"
    r = Request(URI, body=payload)
    assert "bar" not in repr(r)
    assert "<SANITIZED>" in repr(r)


def test_password_body():
    payload = "username=foo&password=bar"
    r = Request(URI, body=payload)
    assert "bar" not in repr(r)
    assert "<SANITIZED>" in repr(r)
    payload = "password=bar&username=foo"
    r = Request(URI, body=payload)
    assert "bar" not in repr(r)
    assert "<SANITIZED>" in repr(r)


def test_headers_params():
    r = Request(URI, headers={"token": "foobar"}, body="token=banana")
    assert r.headers["token"] == "foobar"
    assert r.token == "banana"


def test_sanitized_request_non_debug_mode():
    """make sure requests are sanitized when in non debug mode.
    For the debug mode, the other tests checking sanitization should prove
    that debug mode is working.
    """
    try:
        oauthlib.set_debug(False)
        r = Request(URI, headers={"token": "foobar"}, body="token=banana")
        assert "token" not in repr(r)
        assert "SANITIZED" in repr(r)
    finally:
        # set flag back for other tests
        oauthlib.set_debug(True)


def test_basic():
    cid = CaseInsensitiveDict({})
    cid["a"] = "b"
    cid["c"] = "d"
    del cid["c"]
    assert cid["A"] == "b"
    assert cid["a"] == "b"


def test_update():
    cid = CaseInsensitiveDict({})
    cid.update({"KeY": "value"})
    assert cid["kEy"] == "value"
