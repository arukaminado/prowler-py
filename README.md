# prowler-py
- Python version of https://github.com/toniblyx/prowler
- Prowler is a security tool to perform AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness. It contains all CIS controls listed here https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf and more than 100 additional checks that help on GDPR, HIPAA…

## install
- You can install this tool using pip3:
```
pip install prowler-py
```

## upload to testpypi
```
rm -rf dist build src/prowler_py.egg-info 
python setup.py sdist
python setup.py bdist_wheel
twine upload --repository testpypi dist/*

pip install -i https://test.pypi.org/simple/ prowler-py
```
