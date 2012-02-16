#!/usr/bin/env python

from flask import Flask, request, render_template, redirect, session
from oauthlib.oauth import OAuth
from urlparse import parse_qs
import requests
import os

app = Flask(__name__)

key = "mCA55VGdkg0isw5rVi5Ww"
secret = "y8h2tzximLpXFTspl7FpMURoGKZYAo2Vq1WeYxVwyg"
request_url = "https://api.twitter.com/oauth/request_token"
auth_url = "http://api.twitter.com/oauth/authorize"
access_url = "https://api.twitter.com/oauth/access_token"
update_url = "http://api.twitter.com/1/statuses/update.json" 

@app.route("/")
def demo():
    twitter = OAuth(client_key=key,
                    client_secret=secret)
    header = twitter.auth_header(request_url)
    r = requests.post(request_url, headers={"Authorization":header})
    token = parse_qs(r.text)["oauth_token"][0]
    auth = "{url}?oauth_token={token}".format(url=auth_url, token=token)
    return redirect(auth)

@app.route("/callback", methods=["GET", "POST"])
def callback():
    verifier = request.args.get("oauth_verifier")
    token = request.args.get("oauth_token")
    twitter = OAuth(client_key=key,
                    client_secret=secret,
                    request_token=token,
                    verifier=verifier)
    header = twitter.auth_header(access_url)
    r = requests.post(access_url, headers={"Authorization" : header})
    info = parse_qs(r.text)
    session["access_token"] = info["oauth_token"][0]
    session["token_secret"] = info["oauth_token_secret"][0]
    session["screen_name"] = info["screen_name"][0]
    return """<html><head></head><body>
    <form method="POST" action="/post">
    <input name="status_update" type="text" value="hello"/>
    <input type="submit" value="Send"/>
    </form></body></html>"""

@app.route("/post", methods=["POST"])
def post_update():
    post = { "status" : request.form["status_update"] }
    token_secret = session["token_secret"]
    access_token= session["access_token"]
     
    twitter = OAuth(client_key=key,
                    client_secret=secret,
                    token_secret=token_secret,
                    access_token=access_token)
    header = twitter.auth_header(update_url, post)
    r = requests.post(update_url, data=post, headers={"Authorization": header})
    return redirect("https://twitter.com/#!/%s" % session["screen_name"])

if __name__ == "__main__":
    app.secret_key = os.urandom(24)
    app.run(debug=True)

