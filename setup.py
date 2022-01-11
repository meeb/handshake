import os
import sys
from setuptools import setup, find_packages
from handshake.version import version


with open('README.md', 'rt') as f:
    long_description = f.read()


requirements = ()


setup(
    name = 'handshake',
    version = version,
    url = 'https://github.com/meeb/handshake',
    author = 'https://github.com/meeb',
    author_email = 'meeb@meeb.org',
    description = 'A Python library to create and validate authentication tokens.',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    license = 'BSD',
    include_package_data = True,
    install_requires = requirements,
    packages = find_packages(),
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords = ('handshake', 'auth', 'tokens', 'authentication', 'tickets')
)
