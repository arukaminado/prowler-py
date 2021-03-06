#  Copyright (c) 2020 nalansitan.
#  All rights reserved.

from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='prowler-py',
    version='0.0.5',
    description='Prowler is a security tool to perform AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/nalansitan/prowler-py/',
    author='nalansitan',
    author_email='nalansitan@gmail.com',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    include_package_data=True,
    python_requires='>=3.6',
    install_requires=[
      'boto3',
      'pyyaml',
      'termcolor',
    ],
    entry_points={
        'console_scripts': [
            'prowler=prowler.__main__:main',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/nalansitan/prowler-py/issues',
        'Source': 'https://github.com/nalansitan/prowler-py/',
    },
)
