test:
	nosetests -w tests

pycco:
	find oauthlib -name "*.py" -exec pycco -p -s reST {} \;

pycco-clean:
	rm -rf docs/oauthlib docs/pycco.css
