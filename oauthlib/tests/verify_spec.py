import unittest
import sys
sys.path.append("..")
from oauth import *

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

    def test_generate_params(self):
        """ Testing the utility function generate_params 
            
            Verifying per `section 3.4.1.3`_ of the spec.

            .. _`section 3.4.1.3`_ http://tools.ietf.org/html/rfc5849#section-3.4.1.3
        """
        # Sample taken from section 3.4.1.2 fully decoded and compared to the
        # decoded version in 3.4.1.3.2 (they are equivalent)
        client_key = "9djdj82h48djs9d2"
        access_token = "kkk9d7dh3k39sjv7"
        signature_method = "HMAC-SHA1"

        params = generate_params(client_key, access_token, signature_method)
        self.assertEqual(params["oauth_consumer_key"], client_key)
        self.assertEqual(params["oauth_token"], access_token)
        self.assertEqual(params["oauth_signature_method"], signature_method)
        self.assertIsNotNone(params["oauth_nonce"])
        self.assertIsNotNone(params["oauth_timestamp"])
        self.assertIsNotNone(params["oauth_version"])
    
    def test_signature_base_string(self):
        """ Signature Base String

            Per `section 3.4.1`_ of the spec.

            .. _`section 3.4.1`: http://tools.ietf.org/html/rfc5849#section-3.4.1

        """
        for method, uri, params, correct  in self.samples:
            self.assertEqual(prepare_base_string(method, uri, params), correct)

    def test_authorization_header(self):
        """ Authorization Header

            Per `section 3.5.1`_ of the spec.

            .. _`section 3.5.1`: http://tools.ietf.org/html/rfc5849#section-3.5.1

            Uses HMAC-SHA1 Signature 
            
            Per `section 3.4.2`_ of the spec.

            .. _`section 3.4.2`: http://tools.ietf.org/html/rfc5849#section-3.4.2

        """
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

        # Continuing with the sample, but using dictionary for params
        params = {
            "oauth_consumer_key" : "dpf43f3p2l4k3l03",
            "oauth_token" : "nnch734d00sl2jdk",
            "oauth_nonce" : "kllo9940pd9333jh",
            "oauth_timestamp" : "1191242096",
            "oauth_signature_method" : "HMAC-SHA1",
            "oauth_version" : "1.0",
            "oauth_signature" : correct_signature
        }
        realm = "http://photos.example.net/photos"
        header = prepare_authorization_header(realm, params)

        correct_header = ('OAuth realm="http://photos.example.net/photos", ' +
                          'oauth_nonce="kllo9940pd9333jh", ' +
                          'oauth_timestamp="1191242096", ' +
                          "oauth_consumer_key=\"dpf43f3p2l4k3l03\", " +
                          'oauth_signature_method="HMAC-SHA1", ' +
                          'oauth_version="1.0", ' +
                          'oauth_token="nnch734d00sl2jdk", ' +
                          'oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"')
        self.assertEquals(header, correct_header)

if __name__ == "__main__":
    unittest.main()
