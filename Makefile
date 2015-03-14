develop:
	python setup.py develop

undevelop:
	python setup.py develop --uninstall

test:
	flake8 ec2_security_groups_dumper

clean:
	rm -rf ec2_security_groups_dumper.egg-info/
	rm -rf dist/

release: clean
	python setup.py sdist
	twine upload dist/*
