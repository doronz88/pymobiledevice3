#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# vim: fenc=utf-8
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
#

"""
File name: setup.py
Version: 0.1
Author: gotohack <mathieu.renard@gotohack.org>
Date created: 2016-08-18
"""

from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))
f = path.join(here, 'README.md')

setup(
    name='pymobiledevice',
    version='0.0.1',
    description="Interface with iOS devices",
    url='https://github.com/iOSForensics/pymobiledevice',
    author='gotohack',
    author_email='mathieu.renard@gotohack.org',
    license='GPL',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.5',
    ],

    keywords='pymobiledevice ios iphone ipad ipod',
    packages=find_packages(),
    py_modules=['pymobiledevice'],
    entry_points='',
    install_requires=[
        'construct',
        'm2crypto',
    ],
    extras_require={
        'dev': [''],
        'test': [''],
    },
)
