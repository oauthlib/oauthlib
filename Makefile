test:
	# Test OAuthLib
	tox
	#
	# Try and not break these libraries by running their tests too.
	#
	# Flask-OAuthLib
	git clone https://github.com/lepture/flask-oauthlib.git
	cd flask-oauthlib && cp ../tox.ini . && sed -i 's/py32,py33,py34,//' tox.ini && sed -i '/mock/a \     Flask-SQLAlchemy' tox.ini &&  tox
	rm -rf flask-oauthlib
	# Django-OAuth-Toolkit (has tox.ini already)
	git clone https://github.com/evonove/django-oauth-toolkit.git
	cd django-oauth-toolkit && tox
	rm -rf django-oauth-toolkit
	# Requests-OAuthLib
	git clone https://github.com/requests/requests-oauthlib.git
	cd requests-oauthlib && cp ../tox.ini . && sed -i '/mock/a \     requests' tox.ini && tox
	rm -rf requests-oauthlib

pycco:
	find oauthlib -name "*.py" -exec pycco -p -s reST {} \;

pycco-clean:
	rm -rf docs/oauthlib docs/pycco.css
