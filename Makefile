PYS = py27,py34,pypy

test:
	# Test OAuthLib
	tox -e "$(PYS)"
	#
	# Downstream tests (Don't be evil)
	#
	# Try and not break the libraries below by running their tests too.
	#
	# Unfortunately there is no neat way to run downstream tests AFAIK
	# Until we have a proper downstream testing system we will
	# stick to this Makefile.
	#---------------------------
	# HOW TO ADD NEW DOWNSTREAM LIBRARIES
	#
	# Please specify your library as well as primary contacts.
	# Since these contacts will be addressed with Github mentions they
	# need to be Github users (for now)(sorry Bitbucket).
	#
	#---------------------------
	# Library: lepture/flask-oauthLib
	# Contacts: lepture,widnyana
	git clone https://github.com/lepture/flask-oauthlib.git
	cd flask-oauthlib && cp ../tox.ini . && sed -i 's/py32,py33,py34,//' tox.ini && sed -i '/mock/a \     Flask-SQLAlchemy' tox.ini &&  tox -e "$(PYS)"
	rm -rf flask-oauthlib
	#---------------------------
	# Library: evonove/django-oauth-toolkit
	# Contacts: evonove,masci
	# (note: has tox.ini already)
	git clone https://github.com/evonove/django-oauth-toolkit.git
	cd django-oauth-toolkit && tox -e "$(PYS)"
	rm -rf django-oauth-toolkit
	#---------------------------
	# Library requests/requests-oauthlib
	# Contacts: ib-lundgren,lukasa
	git clone https://github.com/requests/requests-oauthlib.git
	cd requests-oauthlib && cp ../tox.ini . && sed -i '/mock/a \     requests' tox.ini && tox -e "$(PYS)"
	rm -rf requests-oauthlib
	#---------------------------
	#

pycco:
	find oauthlib -name "*.py" -exec pycco -p -s reST {} \;

pycco-clean:
	rm -rf docs/oauthlib docs/pycco.css
