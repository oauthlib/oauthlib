import unittest
import sys
sys.path.append("..")
from oauthlib.oauth import *

class VerifyRFCSpecification(unittest.TestCase):

    # First sample is from 3.4.1.1 String Construction with some characters 
    # changed to uppercase. Uses explicit http port
    
    # The second sample is a modification of the first but
    # using a dictionary rather than a list of touples, with some unicode
    # thrown in for good measure. Note that the second sample only contains 
    # unique query components. Uses explicit default https port
    
    # The third sample builds on the second but uses a non default https port
    samples = [ 
         ("post", 
         "hTTp://exampLE.Com:80/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a3=2 q",
         [  ("oauth_consumer_key", "9djdj82h48djs9d2"), 
            ("oauth_signature_method", "HMAC-SHA1"), 
            ("oauth_token", "kkk9d7dh3k39sjv7"),
            ("oauth_timestamp", "137131201"),
            ("oauth_nonce", "7d8f3e4a")],
            "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b"+
            "%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540"+
            "%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26"+
            "oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1"+
            "%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"
        ),
        ("get", 
         "hTTps://exampLE.Com:443/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a4=2 q",
         {  u"oauth_consumer_key" : "9djdj82h48djs9d2", 
            u"oauth_signature_method" : "HMAC-SHA1", 
            u"oauth_token" : u"kkk9d7dh3k39sjv7",
            u"oauth_timestamp" : "137131201",
            u"oauth_nonce" : u"7d8f3e4a"},
            "GET&https%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b"+
            "%26a3%3Da%26a4%3D2%2520q%26b5%3D%253D%25253D%26c%2540"+
            "%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26"+
            "oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1"+
            "%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"
        ),
        ("head", 
         "hTTps://exampLE.Com:81/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2=&a4=2 q",
         {  u"oauth_consumer_key" : "9djdj82h48djs9d2", 
            u"oauth_signature_method" : "HMAC-SHA1", 
            u"oauth_token" : u"kkk9d7dh3k39sjv7",
            u"oauth_timestamp" : "137131201",
            u"oauth_nonce" : u"7d8f3e4a"},
            "HEAD&https%3A%2F%2Fexample.com%3A81%2Frequest&a2%3Dr%2520b"+
            "%26a3%3Da%26a4%3D2%2520q%26b5%3D%253D%25253D%26c%2540"+
            "%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26"+
            "oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1"+
            "%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"
        )
    ]

    def test_base_string(self):
        for method, uri, params, correct  in self.samples:
            self.assertEqual(prepare_base_string(method, uri, params), correct)

    def test_sign_hmac(self):
        # Using sample from http://hueniverse.com/oauth/guide/authentication/
        method = "GET"
        url = "http://photos.example.net:80/photos?size=original&file=vacation.jpg"
        params = [
            ("oauth_consumer_key", "dpf43f3p2l4k3l03"),
            ("oauth_token", "nnch734d00sl2jdk"),
            ("oauth_nonce", "kllo9940pd9333jh"),
            ("oauth_timestamp", "1191242096"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_version", "1.0")
        ]
        client_secret = "kd94hf93k423kf44"
        access_secret = "pfkkdhi9sl3r4s00"
        signature = sign_hmac(method, url, params, client_secret, access_secret)
        correct_signature = "tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"
        self.assertEquals(signature, correct_signature)

    def test_sign_plain(self):
        # Using sample from http://hueniverse.com/oauth/guide/authentication/
        client_secret = "kd94hf93k423kf44"
        access_secret = "pfkkdhi9sl3r4s00"
        signature = sign_plain(client_secret, access_secret)
        correct_signature = "kd94hf93k423kf44%26pfkkdhi9sl3r4s00"
        self.assertEquals(signature, correct_signature)

    def test_sign_rsa(self):
        # Confirmed against OAuth playground with custom domain and key
        method = "GET"
        url = "https://www.google.com/accounts/OAuthGetRequestToken"

        params = [
            ("oauth_consumer_key", "iblundgren.com"),
            ("oauth_nonce", "0cc8cd31dd7035038d0da266f8cc8d07"),
            ("oauth_timestamp", "1326833510"),
            ("oauth_signature_method", "RSA-SHA1"),
            ("oauth_version", "1.0"),
            ("oauth_callback", ("http://googlecodesamples.com" +
                                "/oauth_playground/index.php"))
        ]
        # Using a 1024 RSA private key stored in private.pem, generated using
        # openssl genrsa -out private.pem 1024
        # Reading from private.pem since there was a bug in my pycrypto 2.3
        # when generating new keys. You may also get warnings about timing 
        # attacks if you are using libgmp < 5
        from Crypto.PublicKey import RSA
        with open("myrsakey.pem") as f:
            key = RSA.importKey(f.read())
        signature = sign_rsa(method, url, params, key.exportKey())

        # The correct signature as generated by Google OAuth playground
        correct_signature = ("lCqPRqU6eVWMczmYBwe1N%2BlSzrm4DcwhTZ2CyrYeh3eo" +
                             "t1akZDqdQFZtB2vLg2cVhSZB3FXNbWOnAjRF1Z7VR%2FU5" + 
                             "faVmsafsTwDxdlsawnQ9kI1Yfu2uQRZrzkKYz71TGpIGaS" +
                             "fdWoLfhU%2B702IAAfB22tt4pQZuwucJSbkRidM%3D")
        self.assertEqual(signature, correct_signature)

        # Reset parameters
        params = [
            ("oauth_consumer_key", "iblundgren.com"),
            ("oauth_nonce", "0cc8cd31dd7035038d0da266f8cc8d07"),
            ("oauth_timestamp", "1326833510"),
            ("oauth_signature_method", "RSA-SHA1"),
            ("oauth_version", "1.0"),
            ("oauth_callback", ("http://googlecodesamples.com" +
                                "/oauth_playground/index.php"))
        ]
       
        # Test if verification works with public key
        pubkey = key.publickey()
        res = verify_rsa(method, url, params, pubkey.exportKey(), signature) 
        self.assertTrue(res)

    def test_authorization_header(self):
        # Using sample from http://hueniverse.com/oauth/guide/authentication/
        params = {
            "oauth_consumer_key" : "dpf43f3p2l4k3l03",
            "oauth_token" : "nnch734d00sl2jdk",
            "oauth_nonce" : "kllo9940pd9333jh",
            "oauth_timestamp" : "1191242096",
            "oauth_signature_method" : "HMAC-SHA1",
            "oauth_version" : "1.0",
            "oauth_signature" : "tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"
        }
        realm = "http://photos.example.net/photos"
        header = prepare_authorization_header(params, realm)

        correct_header = ('OAuth realm="http://photos.example.net/photos", ' +
                          'oauth_nonce="kllo9940pd9333jh", ' + 
                          'oauth_timestamp="1191242096", ' +
                          "oauth_consumer_key=\"dpf43f3p2l4k3l03\", " +
                          'oauth_signature_method="HMAC-SHA1", ' +
                          'oauth_version="1.0", ' +
                          'oauth_token="nnch734d00sl2jdk", ' +
                          'oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"')
        self.assertEquals(header, correct_header)

    def test_form_encoded_body(self):
        # Using sample from http://hueniverse.com/oauth/guide/authentication/
        params = {
            "oauth_consumer_key" : "dpf43f3p2l4k3l03",
            "oauth_token" : "nnch734d00sl2jdk",
            "oauth_nonce" : "kllo9940pd9333jh",
            "oauth_timestamp" : "1191242096",
            "oauth_signature_method" : "HMAC-SHA1",
            "oauth_version" : "1.0",
            "file" : "vacation.jpg",
            "size" : "original",
            "oauth_signature" : "tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"
        }
        header = prepare_form_encoded_body(params)

        correct_header = ('oauth_signature_method=HMAC-SHA1&' +
                          'oauth_consumer_key=dpf43f3p2l4k3l03&'+
                          'oauth_signature=tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D&' +
                          'oauth_timestamp=1191242096&' +
                          'oauth_nonce=kllo9940pd9333jh&' +
                          'oauth_token=nnch734d00sl2jdk&' +
                          'oauth_version=1.0&' +
                          'file=vacation.jpg&' +
                          'size=original')
        self.assertEquals(header, correct_header)

    def test_request_uri_query(self):
        # Using sample from http://hueniverse.com/oauth/guide/authentication/
        params = {
            "oauth_consumer_key" : "dpf43f3p2l4k3l03",
            "oauth_token" : "nnch734d00sl2jdk",
            "oauth_nonce" : "kllo9940pd9333jh",
            "oauth_timestamp" : "1191242096",
            "oauth_signature_method" : "HMAC-SHA1",
            "oauth_version" : "1.0",
            "file" : "vacation.jpg",
            "size" : "original",
            "oauth_signature" : "tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"
        }
        header = prepare_request_uri_query(params, "/call/back")

        correct_header = ('/call/back?'+
                          'oauth_signature_method=HMAC-SHA1&' +
                          'oauth_consumer_key=dpf43f3p2l4k3l03&'+
                          'oauth_signature=tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D&' +
                          'oauth_timestamp=1191242096&' +
                          'oauth_nonce=kllo9940pd9333jh&' +
                          'oauth_token=nnch734d00sl2jdk&' +
                          'oauth_version=1.0&' +
                          'file=vacation.jpg&' +
                          'size=original')
        self.assertEquals(header, correct_header)

    def test_convenience_class(self):
        key = "dpf43f3p2l4k3l03"
        secret = "kd94hf93k423kf44"
        o = OAuth(client_key=key, client_secret=secret)
        url = "http://photos.example.net:80/photos?size=orig$inal&file=vacation.jpg"
        
        h = o.auth_header(url)
        self.assertEqual(o.verify_auth_header(url, h), True)
        
        u = o.uri_query(url)
        self.assertEqual(o.verify_uri_query(u), True)

        f = o.form_body(url)
        self.assertEqual(o.verify_form_body(url, f), True)

        # Now with form/body data
        data = { "hell$" : "w$rld" }

        h = o.auth_header(url, data, realm="photos")
        self.assertEqual(o.verify_auth_header(url, h, data), True)
        
        u = o.uri_query(url, data)
        self.assertEqual(o.verify_uri_query(u, data), True)

        f = o.form_body(url, data)
        self.assertEqual(o.verify_form_body(url, f), True)
        
        # And some tokens!
        token = generate_token()
        token_secret = generate_token(40)
        verifier = generate_token()

        o = OAuth(client_key=key,
                  client_secret=secret,
                  token_secret=token_secret,
                  access_token=token)

        h = o.auth_header(url, data, realm="photos")
        self.assertEqual(o.verify_auth_header(url, h, data), True)
        
        u = o.uri_query(url, data)
        self.assertEqual(o.verify_uri_query(u, data), True)

        f = o.form_body(url, data)
        self.assertEqual(o.verify_form_body(url, f), True)

        # And now signing with rsa
        from Crypto.PublicKey import RSA
        with open("myrsakey.pem") as f:
            rsa_key = RSA.importKey(f.read())

        o = OAuth(client_key=key,
                  rsa_key=rsa_key.exportKey(),
                  signature_method="RSA-SHA1",
                  request_token=token,
                  verifier=verifier)

        s = OAuth(rsa_key=rsa_key.publickey().exportKey(),
                  signature_method="RSA-SHA1")
                  
        h = o.auth_header(url, data, realm="photos")
        self.assertEqual(s.verify_auth_header(url, h, data), True)
        
        u = o.uri_query(url, data)
        self.assertEqual(s.verify_uri_query(u, data), True)

        f = o.form_body(url, data)
        self.assertEqual(s.verify_form_body(url, f), True)
        
        # And lets not forget plaintext!
        o = OAuth(client_key=key,
                  client_secret=secret,
                  callback="http://www.example.com/cb",
                  signature_method="PLAINTEXT")

        h = o.auth_header(url, data, realm="photos")
        self.assertEqual(o.verify_auth_header(url, h, data), True)
        
        u = o.uri_query(url, data)
        self.assertEqual(o.verify_uri_query(u, data), True)

        f = o.form_body(url, data)
        self.assertEqual(o.verify_form_body(url, f), True)

    def test_invalid_convenience_objects(self):
        o = OAuth(signature_method=None)
        p = OAuth(signature_method="RSA-SHA1",
                  client_key="test")
        q = OAuth(access_token="A",
                  request_token="B",
                  client_key="test",
                  client_secret="test")
        r = OAuth(client_key="test",
                  client_secret="test")
        with self.assertRaises(OAuthError):
            o.auth_header(None)
        with self.assertRaises(OAuthError):
            p.auth_header(None)
        with self.assertRaises(OAuthError):
            p.auth_header(None)
        with self.assertRaises(OAuthError):
            r.auth_header(None, 10)


if __name__ == "__main__":
    unittest.main()
