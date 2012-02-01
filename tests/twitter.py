import requests
import sys
sys.path.append("..")
from oauthlib.oauth import *
import time


class OAuthenticator(object):

    def __init__(self, 
                    client_key,
                    url=None,
                    request_method = "POST",
                    client_secret = None,
                    token_secret = None,
                    signature_method="HMAC-SHA1",
                    callback = None):

        self.params = {
            "oauth_consumer_key" : client_key,
            "oauth_signature_method" : signature_method,
            "oauth_timestamp" : generate_timestamp(),
            "oauth_nonce" : generate_nonce(),
            "oauth_version" : "1.0"
        }

        if callback:
            self.params["oauth_callback"] = escape(callback) #TODO: library should escape

        self.client_secret = client_secret
        self.token_secret = token_secret
        self.request_method = request_method
        self.url = url

    def _sign_hmac(self, params):
        return sign_hmac(self.request_method, self.url, params, self.client_secret, self.token_secret)

    def access(self, token, url=None, client_secret=None, token_secret=None, verifier=None, callback=None):
        self.params["oauth_token"] = token
        
        if url:
            self.url = url

        if client_secret:
            self.client_secret = client_secret

        if token_secret:
            self.token_secret = token_secret
        
        if verifier:
            self.params["oauth_verifier"] = verifier
        
        if callback:
            self.params["oauth_callback"] = callback

        self.params["oauth_timestamp"] = generate_timestamp()
        self.params["oauth_nonce"] = generate_nonce()
        # TODO: not hardcoded sign hmac
        self.params["oauth_signature"] = self._sign_hmac(self.params)
        
        # TODO: not hardcode post request
        # Dont hardcode authorization field?
        print self.params
        headers = { "Authorization" : prepare_authorization_header(self.params) }
        print headers
        r = requests.post(self.url, {}, headers=headers)
        from urlparse import parse_qs
        info = parse_qs(r.content)
        self.params["oauth_token"] = info["oauth_token"][0]
        self.token_secret = info["oauth_token_secret"][0]
        del info["oauth_token"]
        del info["oauth_token_secret"]
        return info

    def redirect_token(self):
        self.params["oauth_signature"] = self._sign_hmac(self.params)
        # Dont hardcode authorization field?
        headers = { "Authorization" : prepare_authorization_header(self.params) }
        # TODO: not hardcode post request
        r = requests.post(self.url, {}, headers=headers)
        # TODO: answer might not always be parsable like this...
        from urlparse import parse_qs
        info = parse_qs(r.content)
        return info["oauth_token"][0]

    def header(self, data=None, url=None):
        if url:
            self.url = url

        try:
            del self.params["oauth_callback"]
            del self.params["oauth_verifier"]
        except KeyError:
            pass

        data = data or {}
        data.update(self.params)
        self.params["oauth_signature"] = self._sign_hmac(data)
        return { "Authorization" : prepare_authorization_header(self.params) }


if __name__ == "__main__":

    key = "mCA55VGdkg0isw5rVi5Ww"
    secret = "y8h2tzximLpXFTspl7FpMURoGKZYAo2Vq1WeYxVwyg"
    request_url = "https://api.twitter.com/oauth/request_token"

    o = OAuthenticator(key, url=request_url, client_secret=secret)
    token = o.redirect_token()
    print "http://api.twitter.com/oauth/authorize?oauth_token=" + token 
    
    token = raw_input("Token:")
    verifier = raw_input("Verifier:")
    access_url = "https://api.twitter.com/oauth/access_token"
    print o.access(token, url=access_url, verifier=verifier, callback="http://127.0.0.1")

    print o.header({ "hej" : "svej"}, "http://www.hej.svej")
