#!/usr/bin/env python

from setuptools import setup
import os
import re

setup(name='bonk',
      version='0.7.0',
      license='Apache Software License',
      description='Simple IPAM',
      author='Klarna Bank AB',
      author_email='daniel.zakrisson@klarna.com',
      url='https://github.com/dhozac/bonk',
      packages=['bonk', 'bonk.migrations'],
      install_requires=[
          'netaddr',
          'djangorestframework',
          'django_rethink',
          'requests',
          'dnspython',
      ],
      include_package_data=True,
      zip_safe=True,
      classifiers=[
          'Development Status :: 6 - Mature',
          'Environment :: Web Environment',
          'Framework :: Django :: 1.11',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Topic :: System :: Networking',
      ],
)
