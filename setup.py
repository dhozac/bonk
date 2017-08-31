#!/usr/bin/env python

from setuptools import setup
import os
import re

setup(name='bonk',
      version='0.3.1',
      description='Simple IPAM',
      author='Klarna IT Operations Core Services',
      author_email='itops.core-services@klarna.com',
      url='',
      packages=['bonk', 'bonk.migrations'],
      install_requires=map(lambda x: re.sub(r".*#egg=(.*)", lambda m: m.group(1), x.strip()), open(os.path.join(os.path.dirname(__file__), 'requirements.txt')).readlines()),
      include_package_data=True,
      zip_safe=True,
)
