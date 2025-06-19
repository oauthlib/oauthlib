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
# need to be Github users.
#
clean: clean-eggs clean-build
	@find . -iname '*.pyc' -delete
	@find . -iname '*.pyo' -delete
	@find . -iname '*~' -delete
	@find . -iname '*.swp' -delete
	@find . -iname '__pycache__' -delete
	rm -rf .tox
	rm -rf bottle-oauthlib
	rm -rf dance
	rm -rf django-oauth-toolkit
	rm -rf flask-oauthlib
	rm -rf requests-oauthlib

clean-eggs:
	@find . -name '*.egg' -print0|xargs -0 rm -rf --
	@rm -rf .eggs/

clean-build:
	@rm -fr build/
	@rm -fr dist/
	@rm -fr *.egg-info

test:
	uvx --with tox-uv tox

bottle:
	#---------------------------
	# Library refinitiv/bottle-oauthlib
	# Contacts: Jonathan.Huot
	cd bottle-oauthlib 2>/dev/null || git clone https://github.com/refinitiv/bottle-oauthlib.git
	cd bottle-oauthlib && sed -i.old 's,deps =,deps= --editable=file://{toxinidir}/../,' tox.ini && sed -i.old '/oauthlib/d' requirements.txt && uvx --with tox-uv tox

django:
	#---------------------------
	# Library: evonove/django-oauth-toolkit
	# Contacts: evonove,masci
	cd django-oauth-toolkit 2>/dev/null || git clone https://github.com/evonove/django-oauth-toolkit.git
	cd django-oauth-toolkit && sed -i.old 's,deps =,deps= --editable=file://{toxinidir}/../,' tox.ini && uvx --with tox-uv tox

requests:
	#---------------------------
	# Library requests/requests-oauthlib
	# Contacts: ib-lundgren,lukasa
	cd requests-oauthlib 2>/dev/null || git clone https://github.com/requests/requests-oauthlib.git
	cd requests-oauthlib && sed -i.old 's,oauthlib.*,--editable=file://{toxinidir}/../../[signedtoken],' requirements.txt && uvx --with tox-uv tox

dance:
	#---------------------------
	# Library singingwolfboy/flask-dance
	# Contacts: singingwolfboy
	cd flask-dance 2>/dev/null || git clone https://github.com/singingwolfboy/flask-dance.git
	cd flask-dance && sed -i.old 's;"oauthlib.*";"oauthlib @ file://'`pwd`'/../";' pyproject.toml && uv venv && uv pip install -e '.[test]' && ./.venv/bin/coverage run -m pytest

.DEFAULT_GOAL := all
.PHONY: clean test bottle dance django flask requests
all: test bottle dance django flask requests
