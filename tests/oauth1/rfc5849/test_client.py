# -*- coding: utf-8 -*-
from oauthlib.common import Request
from oauthlib.oauth1 import (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_HMAC_SHA256,
    SIGNATURE_PLAINTEXT,
    SIGNATURE_RSA,
    SIGNATURE_TYPE_BODY,
    SIGNATURE_TYPE_QUERY,
)
from oauthlib.oauth1.rfc5849 import Client

import pytest


def test_client_no_realm():
    client = Client("client-key")
    uri, header, body = client.sign("http://example-uri")
    assert header["Authorization"].startswith("OAuth oauth_nonce=")


def test_client_realm_sign_with_default_realm():
    client = Client("client-key", realm="moo-realm")
    assert client.realm == "moo-realm"
    uri, header, body = client.sign("http://example-uri")
    assert header["Authorization"].startswith('OAuth realm="moo-realm",')


def test_client_realm_sign_with_additional_realm():
    client = Client("client-key", realm="moo-realm")
    uri, header, body = client.sign("http://example-uri", realm="baa-realm")
    assert header["Authorization"].startswith('OAuth realm="baa-realm",')
    assert client.realm == "moo-realm"


def test_convert_to_unicode_resource_owner():
    client = Client("client-key", resource_owner_key=b"owner key")
    assert not isinstance(client.resource_owner_key, bytes)
    assert client.resource_owner_key == "owner key"


def test_give_explicit_timestamp():
    client = Client("client-key", timestamp="1")
    params = dict(client.get_oauth_params(Request("http://example.com")))
    assert params["oauth_timestamp"] == "1"


def test_give_explicit_nonce():
    client = Client("client-key", nonce="1")
    params = dict(client.get_oauth_params(Request("http://example.com")))
    assert params["oauth_nonce"] == "1"


def test_decoding():
    client = Client("client_key", decoding="utf-8")
    uri, headers, body = client.sign("http://a.b/path?query", http_method="POST", body="a=b", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert isinstance(uri, bytes)
    assert isinstance(body, bytes)
    for k, v in headers.items():
        assert isinstance(k, bytes)
        assert isinstance(v, bytes)


def test_hmac_sha1():
    client = Client("client_key")
    assert Client.SIGNATURE_METHODS[SIGNATURE_HMAC_SHA1] == client.SIGNATURE_METHODS[client.signature_method]


def test_hmac_sha256():
    client = Client("client_key", signature_method=SIGNATURE_HMAC_SHA256)
    assert Client.SIGNATURE_METHODS[SIGNATURE_HMAC_SHA256] == client.SIGNATURE_METHODS[client.signature_method]


def test_rsa():
    client = Client("client_key", signature_method=SIGNATURE_RSA)
    assert Client.SIGNATURE_METHODS[SIGNATURE_RSA] == client.SIGNATURE_METHODS[client.signature_method]
    assert client.rsa_key is None


def test_hmac_sha1_method():
    client = Client("client_key", timestamp="1234567890", nonce="abc")
    u, h, b = client.sign("http://example.com")
    correct = 'OAuth oauth_nonce="abc", oauth_timestamp="1234567890", oauth_version="1.0", oauth_signature_method="HMAC-SHA1", oauth_consumer_key="client_key", oauth_signature="hH5BWYVqo7QI4EmPBUUe9owRUUQ%3D"'
    assert h["Authorization"] == correct


def test_hmac_sha256_method():
    client = Client("client_key", signature_method=SIGNATURE_HMAC_SHA256, timestamp="1234567890", nonce="abc")
    u, h, b = client.sign("http://example.com")
    correct = 'OAuth oauth_nonce="abc", oauth_timestamp="1234567890", oauth_version="1.0", oauth_signature_method="HMAC-SHA256", oauth_consumer_key="client_key", oauth_signature="JzgJWBxX664OiMW3WE4MEjtYwOjI%2FpaUWHqtdHe68Es%3D"'
    assert h["Authorization"] == correct


def test_rsa_method():
    private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDk1/bxy"
        "S8Q8jiheHeYYp/4rEKJopeQRRKKpZI4s5i+UPwVpupG\nAlwXWfzXw"
        "SMaKPAoKJNdu7tqKRniqst5uoHXw98gj0x7zamu0Ck1LtQ4c7pFMVa"
        "h\n5IYGhBi2E9ycNS329W27nJPWNCbESTu7snVlG8V8mfvGGg3xNjT"
        "MO7IdrwIDAQAB\nAoGBAOQ2KuH8S5+OrsL4K+wfjoCi6MfxCUyqVU9"
        "GxocdM1m30WyWRFMEz2nKJ8fR\np3vTD4w8yplTOhcoXdQZl0kRoaD"
        "zrcYkm2VvJtQRrX7dKFT8dR8D/Tr7dNQLOXfC\nDY6xveQczE7qt7V"
        "k7lp4FqmxBsaaEuokt78pOOjywZoInjZhAkEA9wz3zoZNT0/i\nrf6"
        "qv2qTIeieUB035N3dyw6f1BGSWYaXSuerDCD/J1qZbAPKKhyHZbVaw"
        "Ft3UMhe\n542UftBaxQJBAO0iJy1I8GQjGnS7B3yvyH3CcLYGy296+"
        "XO/2xKp/d/ty1OIeovx\nC60pLNwuFNF3z9d2GVQAdoQ89hUkOtjZL"
        "eMCQQD0JO6oPHUeUjYT+T7ImAv7UKVT\nSuy30sKjLzqoGw1kR+wv7"
        "C5PeDRvscs4wa4CW9s6mjSrMDkDrmCLuJDtmf55AkEA\nkmaMg2PNr"
        "jUR51F0zOEFycaaqXbGcFwe1/xx9zLmHzMDXd4bsnwt9kk+fe0hQzV"
        "S\nJzatanQit3+feev1PN3QewJAWv4RZeavEUhKv+kLe95Yd0su7lT"
        "LVduVgh4v5yLT\nGa6FHdjGPcfajt+nrpB1n8UQBEH9ZxniokR/IPv"
        "dMlxqXA==\n-----END RSA PRIVATE KEY-----"
    )
    client = Client("client_key", signature_method=SIGNATURE_RSA, rsa_key=private_key, timestamp="1234567890", nonce="abc")
    u, h, b = client.sign("http://example.com")
    correct = (
        'OAuth oauth_nonce="abc", oauth_timestamp="1234567890", '
        'oauth_version="1.0", oauth_signature_method="RSA-SHA1", '
        'oauth_consumer_key="client_key", '
        'oauth_signature="ktvzkUhtrIawBcq21DRJrAyysTc3E1Zq5GdGu8EzH'
        "OtbeaCmOBDLGHAcqlm92mj7xp5E1Z6i2vbExPimYAJL7FzkLnkRE5YEJR4"
        "rNtIgAf1OZbYsIUmmBO%2BCLuStuu5Lg3tAluwC7XkkgoXCBaRKT1mUXzP"
        'HJILzZ8iFOvS6w5E%3D"'
    )
    assert h["Authorization"] == correct


def test_plaintext_method():
    client = Client("client_key", signature_method=SIGNATURE_PLAINTEXT, timestamp="1234567890", nonce="abc", client_secret="foo", resource_owner_secret="bar")
    u, h, b = client.sign("http://example.com")
    correct = 'OAuth oauth_nonce="abc", oauth_timestamp="1234567890", oauth_version="1.0", oauth_signature_method="PLAINTEXT", oauth_consumer_key="client_key", oauth_signature="foo%26bar"'
    assert h["Authorization"] == correct


def test_invalid_method():
    client = Client("client_key", signature_method="invalid")
    with pytest.raises(ValueError, match="Invalid signature method."):
        client.sign("http://example.com")


def test_rsa_no_key():
    client = Client("client_key", signature_method=SIGNATURE_RSA)
    with pytest.raises(ValueError, match="rsa_private_key required for RSA with sha1 signature method"):
        client.sign("http://example.com")


def test_register_method():
    Client.register_signature_method("PIZZA", lambda base_string, client: "PIZZA")
    assert "PIZZA" in Client.SIGNATURE_METHODS
    client = Client("client_key", signature_method="PIZZA", timestamp="1234567890", nonce="abc")
    u, h, b = client.sign("http://example.com")
    assert h["Authorization"] == ('OAuth oauth_nonce="abc", oauth_timestamp="1234567890", oauth_version="1.0", oauth_signature_method="PIZZA", oauth_consumer_key="client_key", oauth_signature="PIZZA"')


def test_params_in_body():
    client = Client("client_key", signature_type=SIGNATURE_TYPE_BODY, timestamp="1378988215", nonce="14205877133089081931378988215")
    _, h, b = client.sign("http://i.b/path", http_method="POST", body="a=b", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert h["Content-Type"] == "application/x-www-form-urlencoded"
    correct = "a=b&oauth_nonce=14205877133089081931378988215&oauth_timestamp=1378988215&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=client_key&oauth_signature=2JAQomgbShqoscqKWBiYQZwWq94%3D"
    assert b == correct


def test_params_in_query():
    client = Client("client_key", signature_type=SIGNATURE_TYPE_QUERY, timestamp="1378988215", nonce="14205877133089081931378988215")
    u, _, _ = client.sign("http://i.b/path", http_method="POST")
    correct = "http://i.b/path?oauth_nonce=14205877133089081931378988215&oauth_timestamp=1378988215&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=client_key&oauth_signature=08G5Snvw%2BgDAzBF%2BCmT5KqlrPKo%3D"
    assert u == correct


def test_invalid_signature_type():
    client = Client("client_key", signature_type="invalid")
    with pytest.raises(ValueError, match="Unknown signature type specified."):
        client.sign("http://i.b/path")


def test_case_insensitive_headers():
    client = Client("client_key")
    _, h, _ = client.sign("http://i.b/path", http_method="POST", body="", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert h["Content-Type"] == "application/x-www-form-urlencoded"
    _, h, _ = client.sign("http://i.b/path", http_method="POST", body="", headers={"content-type": "application/x-www-form-urlencoded"})
    assert h["content-type"] == "application/x-www-form-urlencoded"
    _, h, _ = client.sign("http://i.b/path", http_method="POST", body="", headers={"Content-type": "application/x-www-form-urlencoded"})
    assert h["Content-type"] == "application/x-www-form-urlencoded"
    _, h, _ = client.sign("http://i.b/path", http_method="POST", body="", headers={"conTent-tYpe": "application/x-www-form-urlencoded"})
    assert h["conTent-tYpe"] == "application/x-www-form-urlencoded"


def test_sign_no_body():
    client = Client("client_key", decoding="utf-8")
    with pytest.raises(ValueError, match="Headers indicate a formencoded body but body was not decodable."):
        client.sign("http://i.b/path", http_method="POST", body=None, headers={"Content-Type": "application/x-www-form-urlencoded"})


def test_sign_body():
    client = Client("client_key")
    _, h, b = client.sign("http://i.b/path", http_method="POST", body="", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert h["Content-Type"] == "application/x-www-form-urlencoded"


def test_sign_get_with_body():
    client = Client("client_key")
    for method in ("GET", "HEAD"):
        with pytest.raises(ValueError, match="GET/HEAD requests should not include body."):
            client.sign("http://a.b/path?query", http_method=method, body="a=b", headers={"Content-Type": "application/x-www-form-urlencoded"})


def test_sign_unicode():
    client = Client("client_key", nonce="abc", timestamp="abc")
    _, h, b = client.sign("http://i.b/path", http_method="POST", body="status=%E5%95%A6%E5%95%A6", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert b == "status=%E5%95%A6%E5%95%A6"
    assert 'oauth_signature="yrtSqp88m%2Fc5UDaucI8BXK4oEtk%3D"' in h["Authorization"]
    _, h, b = client.sign("http://i.b/path", http_method="POST", body="status=%C3%A6%C3%A5%C3%B8", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert b == "status=%C3%A6%C3%A5%C3%B8"
    assert 'oauth_signature="oG5t3Eg%2FXO5FfQgUUlTtUeeZzvk%3D"' in h["Authorization"]
